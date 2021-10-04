use std::env;
use std::io;
use std::io::Write;
use std::net;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Instant, Duration};

use std::sync::Arc;
use duration_string::DurationString;
use itertools::Itertools;
use log::{debug, info, warn, error};
use tabwriter::TabWriter;
use rayon::prelude::*;
use rustls::Session;

#[cfg(feature = "local_ip")]
use local_ip_address::local_ip;

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
        let dest_matches = matches.values_of_lossy("dest").unwrap_or_else(Vec::new);
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
}

// Hostnames and results of an DNS/host lookup
#[derive(Clone, Debug)]
struct HostLookup {
    hostname: String,
    ip: Option<net::IpAddr>,
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
        protocol_version: rustls::ProtocolVersion,
    },
    InvalidDNSNameError,
    OpenNoTLS, // aka IncompleteHandshake,
    TlsIoTimeout,
    IoErr(io::Error),
    TlsErr(rustls::TLSError),
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
                let tls_error = error.get_ref().map(|r| r.downcast_ref::<rustls::TLSError>() ).flatten();
                match tls_error {
                    Some(rustls::TLSError::CorruptMessage) => TlsResult::OpenNoTLS,
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

impl From<&rustls::TLSError> for TlsResult {
    fn from(error: &rustls::TLSError) -> Self {
        TlsResult::TlsErr(error.clone())
    }
}

impl From<webpki::InvalidDNSNameError> for TlsResult {
    fn from(_error: webpki::InvalidDNSNameError) -> Self {
        TlsResult::InvalidDNSNameError
    }
}

impl std::fmt::Display for TlsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsResult::TlsOk {
                protocol_version: version
            } => write!(f, "{:?}", version),
            TlsResult::TlsErr(tls_err) => write!(f, "{}", tls_err),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[derive(Debug)]
enum ConnectResult {
    Open {
        local: Option<net::SocketAddr>,
        peer: Option<net::SocketAddr>,
        tls: TlsResult,
    },
    Closed,
    Filtered,
    EmptySocketAddrs,
    LocalIpLookup,
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

impl ConnectResult {
    fn from_open_ips(
        local_sock: std::io::Result<net::SocketAddr>,
        peer_sock: std::io::Result<net::SocketAddr>,
        tls: TlsResult
    ) -> ConnectResult {
        let local = ok_or_log(local_sock, "TCP stream couldn't get local ip");
        let peer = ok_or_log(peer_sock, "TCP stream couldn't get peer ip");
        ConnectResult::Open { local, peer, tls }
    }

    fn from_result(tcp_result: io::Result<net::TcpStream>) -> ConnectResult {
        match tcp_result {
            Ok(stream) => {
                Self::from_open_ips(stream.local_addr(), stream.peer_addr(), TlsResult::NotChecked)
            }
            Err(e) => match e.kind() {
                io::ErrorKind::TimedOut => ConnectResult::Filtered,
                io::ErrorKind::ConnectionRefused => ConnectResult::Closed,
                _ => ConnectResult::OtherIoError(e),
            },
        }
    }

    // It's ok if the connection opened ok,
    // and any TLS handshake succeeded
    fn seems_ok(&self) -> bool {
        match self {
            ConnectResult::Open { tls, .. } => tls.seems_ok(),
            _ => false
        }
    }
}

impl From<io::Result<net::TcpStream>> for ConnectResult {
    // assumed to be only used when Tls is not checked
    fn from(tcp_result: io::Result<net::TcpStream>) -> Self {
        Self::from_result(tcp_result)
    }
}

impl std::fmt::Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Open { tls: TlsResult::NotChecked, .. } => write!(f, "Open"),
            ConnectResult::Open { tls: tls_result, .. } => tls_result.fmt(f),
            ConnectResult::Closed => write!(f, "Closed"),
            ConnectResult::Filtered => write!(f, "Filtered"),
            ConnectResult::EmptySocketAddrs => write!(f, "EmptySocketAddrs"),
            ConnectResult::OtherIoError(e) => write!(f, "Error: {}", e),
            ConnectResult::LocalIpLookup => write!(f,"(local ip)"),
        }
    }
}

#[derive(Debug)]
enum ReportItem {
    Todo(ReportTodo),
    Done(ReportDone),
}

impl ReportItem {
    fn from_sock(pair: ReportConnectionPair, sock: SocketAddr, timeout: Duration) -> ReportItem {
        ReportItem::Todo(ReportTodo { pair, sock, timeout })
    }
    fn from_connect_result(pair: ReportConnectionPair, result: ConnectResult, start: Instant, duration: Duration) -> ReportItem {
        ReportItem::Done(ReportDone::from_connect_result(pair, result, start, duration))
    }
    fn from_io_error(pair: ReportConnectionPair, err: io::Error, start: Instant, duration: Duration) -> ReportItem {
        ReportItem::Done(ReportDone::from_io_error(pair, err, start, duration))
    }
    fn check_connect(self, tls_config: &Option<Arc<rustls::ClientConfig>>) -> ReportDone {
        match self {
            ReportItem::Done(done) => done,
            ReportItem::Todo(todo) => todo.check_connect(tls_config),
        }
    }
}

#[derive(Clone, Debug)]
struct ReportConnectionPair {
    local: HostLookup,
    peer: HostLookup,
    port: u16,
}

#[derive(Debug)]
struct ReportTodo {
    pair: ReportConnectionPair,
    sock: SocketAddr,
    timeout: Duration,
}

impl ReportTodo {

    fn check_tls(self: &ReportTodo, stream: &mut net::TcpStream, timeout: Duration, tls_config: &Arc<rustls::ClientConfig>) -> Result<TlsResult,TlsResult> {
        stream.set_write_timeout(Some(timeout))?;
        stream.set_read_timeout(Some(timeout))?;
        let dns_name = &self.pair.peer.hostname;
        let dns_ref = webpki::DNSNameRef::try_from_ascii_str(dns_name)?;
        let mut client = rustls::ClientSession::new(tls_config, dns_ref);

        let completed = client.complete_io(stream);
        debug!("completed tls io: {:?}", completed);
        completed?;
        let ciphersuite = client.get_negotiated_ciphersuite();
        let protoversion = client.get_protocol_version();
        info!("tls {}: ciphersuite: {:?}, proto {:?}", dns_name, ciphersuite, protoversion);

        client.send_close_notify();
        // finishing close notify is not considered a reportable error
        let _ = client.complete_io(stream);

        Ok(TlsResult::TlsOk {
            protocol_version: client.get_protocol_version().unwrap_or(rustls::ProtocolVersion::Unknown(0))
        })
    }

    fn check_connect(self: ReportTodo, tls_config: &Option<Arc<rustls::ClientConfig>>) -> ReportDone {
        let start = Instant::now();
        let t = net::TcpStream::connect_timeout(
            &self.sock, self.timeout);
        let mut duration = Instant::now() - start;
        debug!("tcp connect addr {:?} returned {:?} in {:?}", self.sock, t, duration);
        // watch out for panic in Sub
        let next_timeout = if self.timeout > duration { self.timeout - duration } else { Duration::from_millis(0) };
        let result = if let Ok(mut stream) = t {
            let local = stream.local_addr();
            let peer = stream.peer_addr();
            let mut tls_result = TlsResult::NotChecked;
            if let Some(tls_config) = tls_config {
                tls_result = self.check_tls(&mut stream, next_timeout, tls_config)
                    .unwrap_or_else(|e| e);
                duration = Instant::now() - start;
            }
            ConnectResult::from_open_ips(local, peer, tls_result)
        } else {
            ConnectResult::from_result(t)
        };
        ReportDone::from_connect_result(self.pair, result, start, duration)
    }
}

#[derive(Debug)]
struct ReportDone {
    pair: ReportConnectionPair,
    result: ConnectResult,
    start: Instant,
    duration: Duration,
}

impl ReportDone {
    fn from_connect_result(pair: ReportConnectionPair, result: ConnectResult,
                           start: Instant, duration: Duration) -> ReportDone {
        match &result {
            // for open connections, replace initial guesses
            // with actual ips used
            ConnectResult::Open {
                local: local_addr,
                peer: peer_addr,
                tls: _tls_result,
            } => ReportDone {
                pair: ReportConnectionPair {
                    local: HostLookup {
                        hostname: pair.local.hostname,
                        ip: local_addr.map(|x| x.ip()),
                    },
                    peer: HostLookup {
                        hostname: pair.peer.hostname,
                        ip: peer_addr.map(|x| x.ip()),
                    },
                    port: pair.port,
                },
                result,
                start,
                duration,
            },
            _ => ReportDone { pair, result, start, duration },
        }
    }

    // especially for errors during host lookup
    fn from_io_error(pair: ReportConnectionPair, err: io::Error, start: Instant, duration: Duration) -> ReportDone {
        ReportDone {
            pair,
            result: ConnectResult::OtherIoError(err),
            start,
            duration,
        }
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

#[cfg(feature = "local_ip")]
fn local_ip_report<W: Write>(tw: &mut TabWriter<W>, src_hostname: &str) -> io::Result<()> {
    // No local IPs?  Add ip lookups to the end
    let local_ip = ok_or_log(local_ip(), "Could not get local ip");
    if let Some(item) = local_ip {
        // item.println(&mut tw)?;
        local_ip_line(tw, HostLookup {
            hostname: src_hostname.to_string(),
            ip: Some(item),
        })?;
    }
    Ok(())
}


// use std to_socket_addrs to attempt
// (this doesn't work where the local hostname is always configured
//  to a loopback address, but has a chance to be better than nothing)
#[cfg(not(feature = "local_ip"))]
fn local_ip_report<W: Write>(tw: &mut TabWriter<W>, src_hostname: &str) -> io::Result<()> {
    let src_addrs = ok_or_log(
        (src_hostname.clone(), 0u16).to_socket_addrs(),
        "Couldn't lookup local hostname guess");
    info!("Local lookup: {} found {:?}", src_hostname, src_addrs);
    let src_guess = if let Some(addrs) = src_addrs {
        addrs
            .map(|addr| addr.ip())
            .filter(|ip| !ip.is_loopback())
            .collect()
    } else {
        vec![]
    };
    for item in &src_guess {
        // item.println(&mut tw)?;
        local_ip_line(tw, HostLookup {
            hostname: src_hostname.to_string(),
            ip: Some(*item),
        })?;
    }
    Ok(())
}

// Returns a Vec collect to_socket_addrs
fn collect_socket_addrs_report(
    pair: ReportConnectionPair,
    sock_addr: net::SocketAddr,
    timeout: Duration,
) -> Result<Vec<ReportItem>, io::Error> {
    // note: to_socket_addrs blocks thread
    let socket_addrs = (sock_addr.ip(), pair.port).to_socket_addrs()?;
    let mut report: Vec<ReportItem> = socket_addrs
        .map(|sock| ReportItem::from_sock(pair.clone(), sock, timeout))
        .collect();
    if report.is_empty() {
        // may happen depending on the outcome resolving to to_socket_addrs
        report.push(ReportItem::from_connect_result(
            pair,
            ConnectResult::EmptySocketAddrs,
            Instant::now(),
            Duration::from_millis(0)
        ))
    }
    Ok(report)
}

fn report_host(
    local_host_lookup: &HostLookup,
    host: &str,
    lookup_port: u16,
    ports: &[u16],
    timeout: Duration,
) -> Result<Vec<ReportItem>, io::Error> {
    let socket_addrs = (host, lookup_port).to_socket_addrs()?;
    let host_report: Vec<_> = socket_addrs
        .map(|s| {
            let peer_info = HostLookup {
                hostname: host.to_string(),
                ip: Some(s.ip()),
            };

            let socket_addr_report: Vec<ReportItem> = ports
                .iter()
                .map(|port| {
                    collect_socket_addrs_report(
                        ReportConnectionPair {
                            local: local_host_lookup.clone(),
                            peer: peer_info.clone(),
                            port: *port,
                        },
                        s,
                        timeout,
                    )
                    .unwrap_or_else(|err| {
                        vec![ReportItem::from_io_error(
                            ReportConnectionPair {
                                local: local_host_lookup.clone(),
                                peer: peer_info.clone(),
                                port: *port,
                            },
                            err,
                            Instant::now(),
                            Duration::from_millis(0),
                        )]
                    })
                })
                .flatten()
                .collect();
            socket_addr_report
        })
        .flatten()
        .collect();
    Ok(host_report)
}

fn report_hosts_ports(local_host_lookup: &HostLookup, group: &HostsPortsGroup, timeout: Duration) -> Vec<ReportItem> {
    // assume that any port will result in the same lookup,
    // so use the first port just to find the dest ip
    let lookup_port = group.ports.get(0).map_or(443, |p| *p);
    group
        .hostnames
        .iter()
        .map(|host| {
            report_host(local_host_lookup, host, lookup_port, &group.ports, timeout)
                .unwrap_or_else(|err| {
                vec![ReportItem::from_io_error(
                    ReportConnectionPair {
                        local: local_host_lookup.clone(),
                        peer: HostLookup {
                            hostname: host.to_string(),
                            ip: None,
                        },
                        port: lookup_port,
                    },
                    err,
                    Instant::now(),
                    Duration::from_millis(0),
                )]
            })
        })
        .flatten()
        .collect()
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

fn rustls_client_config(tls_arg: Option<TlsMode>) -> Option<Arc<rustls::ClientConfig>> {
    if let Some(tls_mode) = tls_arg {
        let mut config = rustls::ClientConfig::new();
        match tls_mode {
            TlsMode::MozillaRoots => {
                config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            }
            TlsMode::NativeRoots => {
                let cert_store = match rustls_native_certs::load_native_certs() {
                    Ok(store) => store,
                    Err((Some(partial), err)) => {
                        warn!("Error loading native platform TLS root cert, using partial roots: {}", err);
                        partial
                    },
                    Err((None, err)) => panic!("Could not load native platform TLS root certs (try --tls-moz?): {}", err)
                };
                config.root_store = cert_store;
            }
        }
        Some(Arc::new(config))
    } else {
        None
    }
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

fn main() -> io::Result<()> {
    env_logger::init();
    const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
    let default_timeout_str = "7s";
    let default_timeout: Duration = DurationString::from_string(default_timeout_str.to_string())
        .unwrap().into();

    let appmatches = clap::App::new("ackreport")
        .version(VERSION.unwrap_or("v0"))
        .arg(
            clap::Arg::with_name("threads")
                .help("Parallel connection attempts (default 10)")
                .multiple(false)
                .long("threads")
                .required(false)
                .takes_value(true)
                .env("RAYON_NUM_THREADS")
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

    let dests = HostsPortsGroup::group_dest_args(&appmatches);
    let src_hostname = get_hostname();
    let mut tw = TabWriter::new(io::stdout());

    let timeout: Duration =
        DurationString::from_string(
            appmatches.value_of("timeout")
                .expect("timeout has default, this must be present")
                .to_string())
            .map(|ds| ds.into())
            .unwrap_or_else(|e| {
                error!("Could not parse timeout arg: {}; using default {:?}", e, default_timeout);
                default_timeout
            });

    let tls_arg = if appmatches.is_present("tls") {
        Some(TlsMode::NativeRoots)
    } else if appmatches.is_present("tls-moz") {
        Some(TlsMode::MozillaRoots)
    } else {
        None
    };
    let tls_config = rustls_client_config(tls_arg);

    let arg_threads = appmatches.value_of("threads");
    if Err(env::VarError::NotPresent) == env::var("RAYON_NUM_THREADS") || arg_threads.is_some() {
        env::set_var(
            "RAYON_NUM_THREADS",
            appmatches.value_of("threads").unwrap_or("10"),
        );
    }

    let local_host_fallback = HostLookup {
        hostname: src_hostname.clone(),
        ip: None,
    };

    let report_todo: Vec<_> = dests
        .iter()
        .map(|group| report_hosts_ports(&local_host_fallback, group, timeout))
        .flatten()
        .collect();

    info!("Checking {} connections", report_todo.len());  // (RUST_LOG=info for timestamp!)
    let report_done: Vec<_> = report_todo.into_par_iter().map(|r| r.check_connect(&tls_config)).collect();

    let any_local_ips = report_done.iter()
        .any(|item| item.has_local_ip());

    ReportDone::header(&mut tw)?;
    for item in &report_done {
        item.println(&mut tw)?;
    }
    if !any_local_ips
    {
        local_ip_report(&mut tw, &src_hostname)?;
    }
    tw.flush()?;

    std::process::exit(report_exit_code(&report_done));
}
