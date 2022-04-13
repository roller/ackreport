use std::convert::TryFrom;
use std::io;
use std::io::Write;
use std::str::FromStr;
use std::net;
use std::net::{SocketAddr, ToSocketAddrs, IpAddr};
use std::sync::Arc;
use std::time::{Instant, Duration};

use duration_string::DurationString;
use itertools::Itertools;
use log::{debug, info, warn, error};
use tabwriter::TabWriter;

#[cfg(feature = "local_ip")]
use local_ip_address::local_ip;
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::OwnedTrustAnchor;
use tokio_rustls::rustls;

// Group hosts and ports to attempt connections
#[derive(Debug)]
struct HostsPortsGroup {
    hostnames: Vec<String>,
    ports: Vec<u16>,
}

impl HostsPortsGroup {
    // group args host1 host2 :22 host3 :33 :44 :55
    // into [{[host1, host2], [22]}, {[host3], [33, 44, 55]}]
    fn group_dest_args(matches: &clap::ArgMatches<'_>) -> Vec<HostsPortsGroup> {
        let dest_matches = matches.values_of_lossy("dest").unwrap_or_default();
        let mut dest_args = dest_matches.iter();
        let mut dests: Vec<HostsPortsGroup> = vec![];
        loop {
            let dest_hosts = dest_args
                .take_while_ref(|s| !s.starts_with(':'))
                .cloned()
                .collect_vec();
            if dest_hosts.is_empty() {
                break;
            }
            let mut dest_ports = dest_args
                .take_while_ref(|s| s.starts_with(':'))
                .flat_map(|s| -> Option<u16> {
                    let s1 = s.trim_start_matches(':');
                    let parsed = s1.parse::<u16>();
                    match parsed {
                        Ok(x) => Some(x),
                        Err(e) => {
                            error!("Couldn't parse port number, ignoring {0}, {1}", s, e);
                            None
                        }
                    }
                })
                .collect_vec();
            if dest_ports.is_empty() {
                // default ports
                dest_ports.extend([80, 443].iter());
            }
            dests.push(HostsPortsGroup {
                hostnames: dest_hosts,
                ports: dest_ports,
            });
        }
        dests
    }

    // first port in group is used for host addr lookup
    fn lookup_port(ports: &[u16]) -> u16 {
       ports.get(0).map_or(443, |p| *p)
    }
}

// Hostnames and results of an DNS/host lookup
#[derive(Clone, Debug)]
struct HostLookup {
    hostname: String,
    ip: Option<IpAddr>,
}

impl std::fmt::Display for HostLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            Some(ip) => {
                let ip_str = ip.to_string();
                if self.hostname == ip_str {
                    write!(f, "{}", ip_str)
                } else {
                    write!(f, "{} {}", self.hostname, ip_str)
                }
            }
            None => write!(f, "{}", self.hostname),
        }
    }
}

#[derive(Debug)]
enum TlsResult {
    NotChecked,
    TlsOk {
        protocol_version: tokio_rustls::rustls::ProtocolVersion,
    },
    InvalidDNSNameError,
    OpenNoTLS, // aka IncompleteHandshake,
    TlsIoTimeout,
    IoErr(io::Error),
    TlsErr(tokio_rustls::rustls::Error),
}

impl TlsResult {
    fn seems_ok(&self) -> bool {
        matches!(self,
            TlsResult::NotChecked |
            TlsResult::TlsOk { .. })
    }
}

impl From<io::Error> for TlsResult {
    fn from(error: io::Error) -> Self {
        let kind = error.kind();
        match kind {
            io::ErrorKind::InvalidData => {
                let tls_error = error.get_ref().and_then(|r| r.downcast_ref::<rustls::Error>());
                match tls_error {
                    Some(rustls::Error::CorruptMessage) => TlsResult::OpenNoTLS,
                    Some(t) => TlsResult::from(t),
                    None => TlsResult::IoErr(error)
                }
            },
            // Example Windows Timeout error:
            // Os { code: 10060, kind: TimedOut, message: "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond." }
            io::ErrorKind::TimedOut => TlsResult::TlsIoTimeout,
            // Example Linux Timeout error:
            // Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }
            io::ErrorKind::WouldBlock => TlsResult::TlsIoTimeout,
            _ => TlsResult::IoErr(error)
        }
    }
}

impl From<&tokio_rustls::rustls::Error> for TlsResult {
    fn from(error: &tokio_rustls::rustls::Error) -> Self {
        TlsResult::TlsErr(error.clone())
    }
}

impl std::fmt::Display for TlsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsResult::TlsOk {
                protocol_version: version
            } => write!(f, "{:?}", version),
            // default message seems a little redundant, e.g.:
            // invalid peer certificate contents: invalid peer certificate: UnknownIssuer
            TlsResult::TlsErr(rustls::Error::InvalidCertificateData(ref data)) => write!(f, "{}", data),
            TlsResult::TlsErr(tls_err) => write!(f, "{}", tls_err),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[derive(Debug)]
struct OpenConnectResult {
    local: Option<net::SocketAddr>,
    peer: Option<net::SocketAddr>,
    tls: TlsResult,
}

#[derive(Debug)]
enum ConnectResult {
    Open(OpenConnectResult),
    Closed,
    LookupTimeout,
    Filtered,
    EmptySocketAddrs,
    LocalIpLookup,
    LookupIoError(io::Error),
    OtherIoError(io::Error),
}

// Convert to option, logging errors
fn ok_or_log<O,E>(res: Result<O,E>, msg: &str) -> Option<O>
    where E: std::fmt::Debug
{
    match res {
        Err(e) => {
            error!("{}: {:?}", msg, e);
            None
        },
        Ok(x) => Some(x)
    }
}

impl OpenConnectResult {
    fn from_open_ips(
        local_sock: std::io::Result<net::SocketAddr>,
        peer_sock: std::io::Result<net::SocketAddr>,
        tls: TlsResult
    ) -> OpenConnectResult {
        let local = ok_or_log(local_sock, "TCP stream couldn't get local ip");
        let peer = ok_or_log(peer_sock, "TCP stream couldn't get peer ip");
        OpenConnectResult { local, peer, tls }
    }
}

impl ConnectResult {

    fn from_io_error(io_error: io::Error) -> ConnectResult {
        match io_error.kind() {
            io::ErrorKind::TimedOut => ConnectResult::Filtered,
            io::ErrorKind::ConnectionRefused => ConnectResult::Closed,
            _ => ConnectResult::OtherIoError(io_error),
        }
    }

    // It's ok if the connection opened ok,
    // and any TLS handshake succeeded
    fn seems_ok(&self) -> bool {
        match self {
            ConnectResult::Open(open_result) => open_result.tls.seems_ok(),
            _ => false
        }
    }
}

impl std::fmt::Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Open(OpenConnectResult {
                                    tls: TlsResult::NotChecked,
                                    ..}) => write!(f, "Open"),
            ConnectResult::Open(OpenConnectResult {
                                    tls: tls_result,
                                    .. }) => tls_result.fmt(f),
            ConnectResult::Closed => write!(f, "Closed"),
            ConnectResult::Filtered => write!(f, "Filtered"),
            ConnectResult::EmptySocketAddrs => write!(f, "EmptySocketAddrs"),
            ConnectResult::LookupTimeout => write!(f, "Lookup: Timeout"),
            ConnectResult::LookupIoError(e) => write!(f, "Lookup: {}", e),
            ConnectResult::OtherIoError(e) => write!(f, "Error: {}", e),
            ConnectResult::LocalIpLookup => write!(f,"(local ip)"),
        }
    }
}

// misnamed, the port makes it more like a triple!
#[derive(Clone, Debug)]
struct ReportConnectionPair {
    local: HostLookup,
    peer: HostLookup,
    port: u16,
}

#[derive(Debug)]
struct ReportDone {
    pair: ReportConnectionPair,
    result: ConnectResult,
    #[allow(dead_code)]
    // Considering moving to Instants rather than Duration
    start: Instant,
    duration: Duration,
}

impl ReportDone {
    fn with_ips(self) -> Self {
        match &self.result {
            // for open connections, replace initial guesses
            // with actual ips used
            ConnectResult::Open (open_result) => ReportDone {
                pair: ReportConnectionPair {
                    local: HostLookup {
                        hostname: self.pair.local.hostname,
                        ip: open_result.local.map(|x| x.ip()),
                    },
                    peer: HostLookup {
                        hostname: self.pair.peer.hostname,
                        ip: open_result.peer.map(|x| x.ip()),
                    },
                    port: self.pair.port,
                },
                .. self
            },
            _ => self
        }
    }

    fn from_connect_result(pair: ReportConnectionPair, result: ConnectResult,
                           start: Instant, duration: Duration) -> ReportDone {
        ReportDone { pair, result, start, duration }.with_ips()
    }

    fn header<W: Write>(tw: &mut TabWriter<W>) -> io::Result<()> {
        writeln!(tw, "Local\tPeer\tPort\tTime\tResult")
    }

    fn has_local_ip(&self) -> bool {
        self.pair.local.ip.is_some()
    }

    fn println<W: Write>(&self, tw: &mut TabWriter<W>) -> io::Result<()> {
        writeln!(
            tw,
            "{}\t{}\t:{}\t{:0.0?}\t{}",
            self.pair.local, self.pair.peer, self.pair.port, self.duration, self.result
        )
    }
}
fn local_ip_line<W: Write>(tw: &mut TabWriter<W>, host_lookup: HostLookup) -> io::Result<()> {
    writeln!(
        tw,
        "{}\t\t\t\t{}",
        host_lookup, ConnectResult::LocalIpLookup
    )
}

fn local_ip_lines<W: Write>(tw: &mut TabWriter<W>, host_ips: Vec<IpAddr>, src_hostname: &str) -> io::Result<()> {
    for ip in host_ips {
        local_ip_line(tw, HostLookup {
            hostname: src_hostname.to_string(),
            ip: Some(ip),
        })?;
    }
    Ok(())
}

#[cfg(feature = "local_ip")]
fn local_ip_report<W: Write>(tw: &mut TabWriter<W>, src_hostname: &str) -> io::Result<()> {
    // No local IPs?  Add ip lookups to the end
    let local_ip = ok_or_log(local_ip(), "Could not get local ip");
    let mut local_ips: Vec<IpAddr> = local_ip.into_iter().collect();
    if local_ips.is_empty() {
        local_ips = guess_local_ip_fallback(src_hostname);
    }
    local_ip_lines(tw, local_ips, src_hostname)
}

fn guess_local_ip_fallback(src_hostname: &str) -> Vec<IpAddr> {
    let src_addrs = ok_or_log(
        (src_hostname, 0u16).to_socket_addrs(),
        "Couldn't lookup local hostname guess");
    info!("Local lookup: {} found {:?}", src_hostname, src_addrs);
    if let Some(addrs) = src_addrs {
        addrs
            .map(|addr| addr.ip())
            .filter(|ip| !ip.is_loopback())
            .collect()
    } else {
        vec![]
    }
}

// use std to_socket_addrs to attempt
// (this doesn't work where the local hostname is always configured
//  to a loopback address, but has a chance to be better than nothing)
#[cfg(not(feature = "local_ip"))]
fn local_ip_report<W: Write>(tw: &mut TabWriter<W>, src_hostname: &str) -> io::Result<()> {
    let src_guess = guess_local_ip_fallback(src_hostname);
    local_ip_lines(tw, src_guess, src_hostname)
}

fn get_hostname() -> String {
    match hostname::get_hostname() {
        Some(hostname) => hostname,
        None => {
            error!("Couldn't get hostname, using localhost");
            "localhost".into()
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum TlsMode {
    NativeRoots,
    MozillaRoots,
}


fn report_exit_code(report: &[ReportDone]) -> i32 {
    if report
        .iter()
        .all(|r| r.result.seems_ok()) {
        0
    } else {
        1
    }
}

const DEFAULT_CONCURRENCY_LIMIT: usize = 10;

// startup config
struct AckReportConfig {
    targets: Vec<HostsPortsGroup>,
    timeout: Duration,
    // rayon uses env strings for config
    threads: Option<String>,
    tls_client_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
}

impl AckReportConfig {
    fn new() -> AckReportConfig {
        const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
        let default_timeout_str = "7s";
        let default_concurrency_str = "10";
        let default_timeout: Duration = DurationString::from_string(default_timeout_str.to_string())
            .unwrap().into();
        let matches = clap::App::new("ackreport")
            .version(VERSION.unwrap_or("v0"))
            .arg(
                // Integration with github workflows
                clap::Arg::with_name("release-workflow-commands")
                    .long("release-workflow-commands")
                    .hidden(true)
                    .takes_value(false)
            )
            .arg(
                clap::Arg::with_name("threads")
                    .help("Parallel connection attempts")
                    .multiple(false)
                    .long("threads")
                    .required(false)
                    .takes_value(true)
                    .default_value(default_concurrency_str)
            )
            .arg(
                clap::Arg::with_name("timeout")
                    .help("Connection timeout (eg 10s or 500ms)")
                    .short("t")
                    .long("timeout")
                    .required(false)
                    .takes_value(true)
                    .default_value(default_timeout_str)
            )
            .arg(
                clap::Arg::with_name("dest")
                    .help("Destination hostnames and :ports")
                    .multiple(true)
                    .required(true)
            )
            .arg(
                clap::Arg::with_name("tls")
                    .help("Attempt TLS handshake with OS cert roots")
                    .long("tls")
                    .alias("tls-native-roots")
                    .takes_value(false)
            )
            .arg(
                clap::Arg::with_name("tls-moz")
                    .help("Attempt TLS handshake with mozilla cert roots")
                    .long("tls-moz")
                    .alias("tls-moz-roots")
                    .alias("tls-mozilla-roots")
                    .takes_value(false)
                    .conflicts_with("tls")
            )
            .get_matches();

        if matches.is_present("release-workflow-commands") {
            println!("::set-output name=version::{}", VERSION.unwrap_or("v0"));
            println!("::set-output name=os_name::{}", std::env::consts::OS);
            println!("::set-output name=arch_name::{}", std::env::consts::ARCH);
            println!("::set-output name=exe_suffix::{}", std::env::consts::EXE_SUFFIX);
            std::process::exit(0);
        }
        let timeout: Duration =
            DurationString::from_string(
                matches.value_of("timeout")
                    .expect("timeout has default, this must be present")
                    .to_string())
                .map(|ds| ds.into())
                .unwrap_or_else(|e| {
                    error!("Could not parse timeout arg: {}; using default {:?}", e, default_timeout);
                    default_timeout
                });

        let tls_mode = if matches.is_present("tls") {
            Some(TlsMode::NativeRoots)
        } else if matches.is_present("tls-moz") {
            Some(TlsMode::MozillaRoots)
        } else {
            None
        };
        let tls_client_config = AckReportConfig::rustls_client_config_from_mode(tls_mode);

        let threads_str: Option<&str> = matches.value_of("threads");
        let threads = threads_str.map(str::to_string);

        let targets = HostsPortsGroup::group_dest_args(&matches);

        AckReportConfig {
            targets,
            timeout,
            threads,
            tls_client_config,
        }
    }

    fn concurrency_limit(&self) -> usize {
        let threads = if let Some(s) = &self.threads {
            ok_or_log(usize::from_str(s), "Could not parse threads arg")
        } else {
            None
        };
        threads.unwrap_or(DEFAULT_CONCURRENCY_LIMIT)
    }

    // Convert webpki roots
    fn webpki_roots_cert_store() -> tokio_rustls::rustls::RootCertStore
    {
        let mut cert_store = tokio_rustls::rustls::RootCertStore::empty();
        let trust_anchors = webpki_roots::TLS_SERVER_ROOTS.0.iter()
            .map(|anchor| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    anchor.subject,
                    anchor.spki,
                    anchor.name_constraints
                )
            });
        cert_store.add_server_trust_anchors(trust_anchors);
        cert_store
    }

    fn rustls_client_config_from_mode(tls_arg: Option<TlsMode>) -> Option<Arc<tokio_rustls::rustls::ClientConfig>> {
        if let Some(tls_mode) = tls_arg {
            let builder_wants_verifier = tokio_rustls::rustls::ClientConfig::builder()
                .with_safe_defaults();

            let cert_store: tokio_rustls::rustls::RootCertStore = match tls_mode {
                TlsMode::MozillaRoots => {
                    Self::webpki_roots_cert_store()
                }
                TlsMode::NativeRoots => {
                    let certs = match rustls_native_certs::load_native_certs() {
                        Ok(store) => store,
                        Err(err) => panic!("Could not load native platform TLS root certs (try --tls-moz?): {}", err)
                    };
                    // config.root_store = cert_store;
                    let mut new_store = tokio_rustls::rustls::RootCertStore::empty();
                    for cert in certs.into_iter() {
                        let res = new_store.add(&tokio_rustls::rustls::Certificate(cert.0));
                        ok_or_log(res, "Couldn't load native cert");
                    }
                    new_store
                }
            };
            let builder2 = builder_wants_verifier.with_root_certificates(cert_store);
            let builder3 = builder2.with_no_client_auth();
            Some(Arc::new(builder3))
        } else {
            None
        }
    }
}

struct AckRunnerState {
    config: AckReportConfig,
    concurrency_limit: tokio::sync::Semaphore,
    local_host_fallback: HostLookup,
}

#[derive(Clone)]
struct AckRunner(Arc<AckRunnerState>);

impl AckRunner {
    fn new(config: AckReportConfig) -> AckRunner {
        let concurrency_limit = tokio::sync::Semaphore::new(config.concurrency_limit());
        let src_hostname = get_hostname();
        let local_host_fallback = HostLookup {
            hostname: src_hostname,
            ip: None,
        };
        AckRunner(
            std::sync::Arc::new(
                AckRunnerState {
                    config,
                    concurrency_limit,
                    local_host_fallback
                }
            )
        )
    }

    async fn run_report_tls(
        &self,
        mut open_result: OpenConnectResult,
        pair: ReportConnectionPair,
        stream: tokio::net::TcpStream,
        start: Instant,
        tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> ReportDone
    {
        let dns_name = &pair.peer.hostname;
        let server_name_result = tokio_rustls::rustls::ServerName::try_from(dns_name.as_ref());
        let server_name = match server_name_result {
            Err(invalid_dns) => {
                open_result.tls = TlsResult::InvalidDNSNameError;
                let duration = Instant::now() - start;
                let result = ConnectResult::Open(open_result);
                warn!("{}: invalid DNS name {:?}", dns_name, invalid_dns);
                return ReportDone::from_connect_result(pair, result, start, duration);
            }
            Ok(server_name) => server_name
        };
        let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
        let connect = connector.connect(server_name, stream);
        let tls_result = tokio::time::timeout(
            self.0.config.timeout,
            connect
        ).await;
        open_result.tls = match tls_result {
            Err(_) => TlsResult::TlsIoTimeout,
            Ok(Err(io_err)) => TlsResult::from(io_err),
            Ok(Ok(mut tls_stream)) => {
                let ciphersuite = tls_stream.get_ref().1.negotiated_cipher_suite();
                let protoversion = tls_stream.get_ref().1.protocol_version();
                info!("tls {}: ciphersuite: {:?}, proto {:?}", dns_name, ciphersuite, protoversion);
                // note: no timeout on shutdown
                let _ = tls_stream.shutdown().await;
                TlsResult::TlsOk {
                    protocol_version: protoversion.unwrap_or(rustls::ProtocolVersion::Unknown(0))
                }
            }
        };
        let duration = Instant::now() - start;
        let result = ConnectResult::Open(open_result);
        ReportDone::from_connect_result(pair, result, start, duration)
    }

    async fn run_report_stream(
        &self,
        pair: ReportConnectionPair,
        addr: &SocketAddr,
        stream: tokio::net::TcpStream,
        start: Instant,
    ) -> ReportDone
    {
        let open_result = OpenConnectResult::from_open_ips(
            stream.local_addr(),
            stream.peer_addr(),
            TlsResult::NotChecked
        );
        let time_done = Instant::now();
        let duration = time_done - start;
        debug!("tcp connect addr {:?} returned {:?} in {:?}", addr, stream, duration);
        if let Some(tls_config) = &self.0.config.tls_client_config {
            self.run_report_tls(open_result, pair, stream, start, tls_config.clone()).await
        } else {
            let result = ConnectResult::Open(open_result);
            ReportDone::from_connect_result(pair, result, start, duration)
        }
    }

    async fn run_report_addr(
        self,
        peer: HostLookup,
        mut host_addr: SocketAddr,
        port: u16,
    ) -> ReportDone
    {
        host_addr.set_port(port);
        let _permit = self.0.concurrency_limit.acquire().await.unwrap();
        let pair = ReportConnectionPair {
            local: self.0.local_host_fallback.clone(),
            peer: peer.clone(),
            port,
        };
        let start = Instant::now();
        let result = tokio::time::timeout(
            self.0.config.timeout, tokio::net::TcpStream::connect(host_addr),
        ).await;
        let time_connect = Instant::now();
        match result {
            Ok(Ok(stream)) => {
                self.run_report_stream(
                    pair, &host_addr, stream, start).await
            }
            Ok(Err(io_error)) => {
                ReportDone::from_connect_result(
                    pair, ConnectResult::from_io_error(io_error), start, time_connect - start)
            }
            Err(_) => {
                ReportDone::from_connect_result(
                    pair, ConnectResult::Filtered, start, time_connect - start)
            }
        }
    }

    async fn run_report_target_name(
        self,
        target_host: String,
        target_ports: Vec<u16>,
    ) -> Vec<ReportDone>
    {
        let start: Instant;
        let lookup_port = HostsPortsGroup::lookup_port(&target_ports);
        let target_host_str: &str = &target_host;
        let mut reports = vec![];
        let mut tasks = vec![];
        let addr_result = {
            let _permit = self.0.concurrency_limit.acquire().await.unwrap();
            start = Instant::now();
            tokio::time::timeout(
                self.0.config.timeout,
                tokio::net::lookup_host((target_host_str, lookup_port))
            ).await
        };
        let time_lookup = Instant::now();
        let no_ip_peer = HostLookup {
            hostname: target_host.to_string(),
            ip: None
        };
        let pair = ReportConnectionPair {
            local: self.0.local_host_fallback.clone(),
            peer: no_ip_peer.clone(),
            port: lookup_port,
        };
        match addr_result {
            Ok(Ok(addrs)) => {
                let mut any_addrs = false;
                for host_addr in addrs {
                    any_addrs = true;
                    let target_ports = target_ports.clone();
                    for port in target_ports {
                        let clone = self.clone();
                        let peer = HostLookup {
                            hostname: no_ip_peer.hostname.clone(),
                            ip: Some(host_addr.ip()),
                        };
                        tasks.push(tokio::spawn(async move {
                            clone.run_report_addr(peer, host_addr, port).await
                        }));
                    }
                }
                if !any_addrs {
                    reports.push(ReportDone::from_connect_result(
                        pair,
                        ConnectResult::EmptySocketAddrs,
                            start,
                        time_lookup - start
                    ));
                }
            }
            Ok(Err(io_error)) => {
                reports.push(ReportDone::from_connect_result(
                    pair,
                    ConnectResult::LookupIoError(io_error),
                    start,
                    time_lookup - start));

            }
            Err(_) => {
                reports.push(ReportDone::from_connect_result(
                    pair,
                    ConnectResult::LookupTimeout,
                    start,
                    time_lookup - start));
            }
        }
        for task in tasks {
            let task_result = task.await;
            if let Ok(report) = task_result {
                reports.push(report);
            }
        }
        reports
    }

    async fn run_report(&self) -> Vec<ReportDone> {
        let mut report: Vec<ReportDone> = Vec::new();
        let mut tasks = vec![];
        for group in &self.0.config.targets {
            for host in &group.hostnames {
                let clone = self.clone();
                let target_host = host.clone();
                let target_ports = group.ports.clone();
                tasks.push( tokio::spawn(async move {
                    clone.run_report_target_name(target_host, target_ports).await
                }));
            }
        }
        for task in tasks {
            let mut batch = task.await.unwrap_or_default();
            report.append(&mut batch);
        }
        report
    }
}

#[cfg(feature = "tracing")]
fn console_subscriber_init(){
    console_subscriber::init();
}

#[cfg(not(feature = "tracing"))]
fn console_subscriber_init(){}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    console_subscriber_init();

    let config = AckReportConfig::new();
    let ack_runner = AckRunner::new(config);

    // info!("Found {} target peers in {:?}", report_todo.len(), lookup_duration);  // (RUST_LOG=info for timestamp!)
    info!("Starting report");  // (RUST_LOG=info for timestamp!)
    let report_done = ack_runner.run_report().await;

    let any_local_ips = report_done.iter()
        .any(|item| item.has_local_ip());

    let mut tw = TabWriter::new(io::stdout());
    ReportDone::header(&mut tw)?;
    for item in &report_done {
        item.println(&mut tw)?;
    }
    if !any_local_ips
    {
        local_ip_report(&mut tw, &ack_runner.0.local_host_fallback.hostname)?;
    }
    tw.flush()?;
    let exit_code = std::io::Result::Ok(report_exit_code(&report_done))?;
    std::process::exit(exit_code);
}
