use std::env;
use std::io;
use std::io::Write;
use std::net;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Instant, Duration};

use duration_string::DurationString;
use itertools::Itertools;
use log::{debug, error, log};
use tabwriter::TabWriter;
use rayon::prelude::*;

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
            Some(ip) => write!(f, "{} {}", self.hostname, ip),
            None => write!(f, "{}", self.hostname),
        }
    }
}

#[derive(Debug)]
enum ConnectResult {
    Open {
        local: net::SocketAddr,
        peer: net::SocketAddr,
    },
    Closed,
    Filtered,
    EmptySocketAddrs,
    OtherIoError(io::Error),
}

impl From<io::Result<net::TcpStream>> for ConnectResult {
    fn from(result: io::Result<net::TcpStream>) -> ConnectResult {
        match result {
            Ok(stream) => {
                let local = stream.local_addr();
                let peer = stream.peer_addr();
                ConnectResult::Open {
                    local: local.expect("TCP stream should have local IP"),
                    peer: peer.expect("TCP stream should have peer IP"),
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

impl std::fmt::Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Open { .. } => write!(f, "Open"),
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
}

impl From<ReportItem> for ReportDone {
    fn from(item: ReportItem) -> ReportDone {
        match item {
            ReportItem::Done(done) => done,
            ReportItem::Todo(todo) => todo.check_connect(),
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
    timeout: Duration
}

impl ReportTodo {
    fn check_connect(self: ReportTodo) -> ReportDone {
        let start = Instant::now();
        let t = net::TcpStream::connect_timeout(
            &self.sock, self.timeout);
        let duration = Instant::now() - start;
        debug!("tcp connect addr {:?} returned {:?} in {:?}", self.sock, t, duration);
        ReportDone::from_connect_result(self.pair, t.into(), start, duration)
    }
}

#[derive(Debug)]
struct ReportDone {
    pair: ReportPair,
    result: ConnectResult,
    start: Instant,
    duration: Duration
}

impl ReportDone {
    fn from_connect_result(pair: ReportPair, result: ConnectResult,
                           start: Instant, duration: Duration)-> ReportDone {
        match result {
            // for open connections, replace initial guesses
            // with actual ips used
            ConnectResult::Open {
                local: local_addr,
                peer: peer_addr,
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
        let r = writeln!(tw, "Local\tPeer\tPort\tResult\tTime");
        if let Err(e) = r {
            error!("Error writing header: {}", e);
        }
    }

    fn println<W: Write>(&self, tw: &mut TabWriter<W>) {
        let r = writeln!(
            tw,
            "{}\t{}\t:{}\t{}\t{}",
            self.pair.local, self.pair.peer, self.pair.port, self.result,
            DurationString::from(self.duration)
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
                .env("RAYON_NUM_THREADS"),
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
                .required(true),
        )
        .arg(
            clap::Arg::with_name("interfaces")
                .help("Show interfaces")
                .short("i")
                .long("interfaces")
                .takes_value(false),
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

    let report_done: Vec<_> = report_todo.into_par_iter().map(ReportDone::from).collect();

    ReportDone::header(&mut tw);
    for item in report_done {
        item.println(&mut tw);
    }

    if let Err(e) = tw.flush() {
        error!("Couldn't flush tab writer: {}", e);
    }
}
