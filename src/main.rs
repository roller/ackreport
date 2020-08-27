use std::env;
use std::io;
use std::io::Write;
use std::net;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Instant, Duration};

use std::sync::Arc;
use duration_string::DurationString;
use itertools::Itertools;
use log::{debug, info, error};
use tabwriter::TabWriter;
use rayon::prelude::*;
use rustls::Session;

// Group of hosts and ports to attempt connections
#[derive(Debug)]
struct HostsPortsGroup {
    hostnames: Vec<String>,
    ports: Vec<u16>,
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
    IncompleteHandshake,
    TlsIoTimeout,
    IoErr(io::Error),
    TlsErr(rustls::TLSError)
}


impl From<io::Error> for TlsResult {
    fn from(error: io::Error) -> Self {
        let kind = error.kind();
        match kind {
            io::ErrorKind::InvalidData => {
                let tls_error = error.get_ref().map(|r| r.downcast_ref::<rustls::TLSError>() ).flatten();
                match tls_error {
                    Some(rustls::TLSError::CorruptMessage) => TlsResult::IncompleteHandshake,
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
        local: net::SocketAddr,
        peer: net::SocketAddr,
        tls: TlsResult,
    },
    Closed,
    Filtered,
    EmptySocketAddrs,
    OtherIoError(io::Error),
}


impl ConnectResult {
    fn from_result(tcp_result: io::Result<net::TcpStream>, tls_result: TlsResult) -> ConnectResult {
        match tcp_result {
            Ok(stream) => {
                let local = stream.local_addr();
                let peer = stream.peer_addr();
                ConnectResult::Open {
                    local: local.expect("TCP stream should have local IP"),
                    peer: peer.expect("TCP stream should have peer IP"),
                    tls: tls_result,
                }
            }
            Err(e) => match e.kind() {
                io::ErrorKind::TimedOut => ConnectResult::Filtered,
                io::ErrorKind::ConnectionRefused => ConnectResult::Closed,
                _ => ConnectResult::OtherIoError(e),
            },
        }
    }
}

impl From<io::Result<net::TcpStream>> for ConnectResult {
    // assumed to be only used when Tls is not checked
    fn from(tcp_result: io::Result<net::TcpStream>) -> Self {
        Self::from_result(tcp_result, TlsResult::NotChecked)
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
        }
    }
}

#[derive(Debug)]
enum ReportItem {
    Todo(ReportTodo),
    Done(ReportDone),
}

impl ReportItem {
    fn from_sock(pair: ReportPair, sock: SocketAddr, timeout: Duration) -> ReportItem {
        ReportItem::Todo(ReportTodo { pair, sock, timeout })
    }
    fn from_connect_result(pair: ReportPair, result: ConnectResult, start: Instant, duration: Duration) -> ReportItem {
        ReportItem::Done(ReportDone::from_connect_result(pair, result, start, duration))
    }
    fn from_io_error(pair: ReportPair, err: io::Error, start: Instant, duration: Duration) -> ReportItem {
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
struct ReportPair {
    local: HostLookup,
    peer: HostLookup,
    port: u16,
}

#[derive(Debug)]
struct ReportTodo {
    pair: ReportPair,
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

        // TODO: Find some useful cert info information to log (subject, san, valid dates)
        /*
        if let Some(certs) = client.get_peer_certificates() {
            for cert in certs {
                info!("peer cert: {:?}", cert);
            }
        }
        */

        client.send_close_notify();
        // finishing close notify is not considered a reportable error
        let _ = client.complete_io(stream);

        Ok(TlsResult::TlsOk {
            protocol_version: client.get_protocol_version().unwrap_or(rustls::ProtocolVersion::Unknown(0))
        })
    }

    fn check_connect(self: ReportTodo, tls_config: &Option<Arc<rustls::ClientConfig>>) -> ReportDone {
        let start = Instant::now();
        let mut t = net::TcpStream::connect_timeout(
            &self.sock, self.timeout);
        let mut duration = Instant::now() - start;
        debug!("tcp connect addr {:?} returned {:?} in {:?}", self.sock, t, duration);
        // watch out for panic in Sub
        let next_timeout = if self.timeout > duration { self.timeout - duration } else { Duration::from_millis(0) };
        let mut tls_result = TlsResult::NotChecked;
        if let Ok(mut stream) = t {
            if let Some(tls_config) = tls_config {
                tls_result = self.check_tls(&mut stream, next_timeout, tls_config)
                    .unwrap_or_else(|e| e);
                duration = Instant::now() - start;
            }
            t = Ok(stream)
        }
        let result = ConnectResult::from_result(t, tls_result);
        ReportDone::from_connect_result(self.pair, result, start, duration)
    }
}

#[derive(Debug)]
struct ReportDone {
    pair: ReportPair,
    result: ConnectResult,
    start: Instant,
    duration: Duration,
}

impl ReportDone {
    fn from_connect_result(pair: ReportPair, result: ConnectResult,
                           start: Instant, duration: Duration)-> ReportDone {
        match &result {
            // for open connections, replace initial guesses
            // with actual ips used
            ConnectResult::Open {
                local: local_addr,
                peer: peer_addr,
                tls: _tls_result,
            } => ReportDone {
                pair: ReportPair {
                    local: HostLookup {
                        hostname: pair.local.hostname,
                        ip: Some(local_addr.ip()),
                    },
                    peer: HostLookup {
                        hostname: pair.peer.hostname,
                        ip: Some(peer_addr.ip()),
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
    fn from_io_error(pair: ReportPair, err: io::Error, start: Instant, duration: Duration) -> ReportDone {
        ReportDone {
            pair,
            result: ConnectResult::OtherIoError(err),
            start,
            duration,
        }
    }

    fn header<W: Write>(tw: &mut TabWriter<W>) {
        let r = writeln!(tw, "Local\tPeer\tPort\tTime\tResult");
        if let Err(e) = r {
            error!("Error writing header: {}", e);
        }
    }

    fn println<W: Write>(&self, tw: &mut TabWriter<W>) {
        let r = writeln!(
            tw,
            "{}\t{}\t:{}\t{:0.0?}\t{}",
            self.pair.local, self.pair.peer, self.pair.port, self.duration, self.result
        );
        if let Err(e) = r {
            error!("Error writing report item: {}", e);
        }
    }
}

// helper to check if addr has a broadcast interface
trait HasBroadcast {
    fn has_broadcast(&self) -> bool;
}
impl HasBroadcast for get_if_addrs::IfAddr {
    fn has_broadcast(&self) -> bool {
        match self {
            get_if_addrs::IfAddr::V4(i) => i.broadcast.is_some(),
            get_if_addrs::IfAddr::V6(i) => i.broadcast.is_some(),
        }
    }
}
impl HasBroadcast for get_if_addrs::Interface {
    fn has_broadcast(&self) -> bool {
        self.addr.has_broadcast()
    }
}

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

// Returns a Vec to collect to_socket_addrs, which
// returns an iterator
fn report_host_port(
    pair: ReportPair,
    sock_addr: net::SocketAddr,
    timeout: Duration,
) -> Result<Vec<ReportItem>, io::Error> {
    let socket_addrs = (sock_addr.ip(), pair.port).to_socket_addrs()?;
    let mut report: Vec<ReportItem> = socket_addrs
        .map(|sock| ReportItem::from_sock(pair.clone(), sock, timeout))
        .collect();
    if report.is_empty() {
        // should never happen, but if it does, report it
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
                    report_host_port(
                        ReportPair {
                            local: local_host_lookup.clone(),
                            peer: peer_info.clone(),
                            port: *port,
                        },
                        s,
                        timeout,
                    )
                    .unwrap_or_else(|err| {
                        vec![ReportItem::from_io_error(
                            ReportPair {
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
                    ReportPair {
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

fn report_interfaces<W: Write>(mut tw: &mut TabWriter<W>, src_hostname: &str) {
    let mut host_name_ip = vec![];
    match get_if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            host_name_ip.extend(
                interfaces
                    .into_iter()
                    .map(|i| {
                        debug!("interface {:?}", i);
                        i
                    })
                    .filter(|i| !i.is_loopback() && i.has_broadcast())
                    .map(|i| HostLookup {
                        hostname: src_hostname.into(),
                        ip: Some(i.ip()),
                    }),
            );
        }
        Err(err) => {
            error!("Couldn't get local interfaces: {}", err);
        }
    }
    writeln!(&mut tw, "Local Interfaces").unwrap();
    for i in &host_name_ip {
        writeln!(&mut tw, "{}", i).unwrap();
    }
    if let Err(e) = tw.flush() {
        error!("Couldn't flush tab writer: {}", e);
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum TlsMode {
    NativeRoots,
    MozillaRoots,
}



fn main() {
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
                .default_value(&default_timeout_str)
        )
        .arg(
            clap::Arg::with_name("dest")
                .help("Destination hostnames and :ports")
                .multiple(true)
                .required(true)
        )
        .arg(
            clap::Arg::with_name("interfaces")
                .help("Show interfaces")
                .short("i")
                .long("interfaces")
                .takes_value(false)
        )
        .arg(
            clap::Arg::with_name("tls")
                .help("Attempt TLS negotiation with OS cert roots")
                .long("tls")
                .alias("tls-native-roots")
                .takes_value(false)
        )
        .arg(
            clap::Arg::with_name("tls-moz-roots")
                .help("Attempt TLS with mozilla cert roots")
                .long("tls-moz-roots")
                .alias("tls-mozilla-roots")
                .takes_value(false)
                .conflicts_with("tls")
        )
        .get_matches();

    let dests = group_dest_args(&appmatches);
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

    if appmatches.is_present("interfaces") {
        report_interfaces(&mut tw, &src_hostname)
    }

    let tls_arg = if appmatches.is_present("tls") {
        Some(TlsMode::NativeRoots)
    } else if appmatches.is_present("tls-moz-roots") {
        Some(TlsMode::MozillaRoots)
    } else {
        None
    };
    let tls_config = if let Some(tls_mode) = tls_arg {
        let mut config = rustls::ClientConfig::new();
        match tls_mode {
            TlsMode::MozillaRoots => {
                config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            }
            TlsMode::NativeRoots => {
                let cert_store = rustls_native_certs::load_native_certs().expect("Could not load native platform TLS root certs (try --tls-moz-roots?)");
                config.root_store = cert_store;
            }
        }
        Some(Arc::new(config))
    } else {
        None
    };

    let arg_threads = appmatches.value_of("threads");
    if Err(env::VarError::NotPresent) == env::var("RAYON_NUM_THREADS") || arg_threads.is_some() {
        env::set_var(
            "RAYON_NUM_THREADS",
            appmatches.value_of("threads").unwrap_or("10"),
        );
    }

    let local_host_fallback = HostLookup {
        hostname: src_hostname,
        ip: None,
    };

    let report_todo: Vec<_> = dests
        .iter()
        .map(|group| report_hosts_ports(&local_host_fallback, &group, timeout))
        .flatten()
        .collect();

    let report_done: Vec<_> = report_todo.into_par_iter().map(|r| r.check_connect(&tls_config)).collect();

    ReportDone::header(&mut tw);
    for item in report_done {
        item.println(&mut tw);
    }

    if let Err(e) = tw.flush() {
        error!("Couldn't flush tab writer: {}", e);
    }
}
