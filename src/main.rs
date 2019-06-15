use std::io;
use crate::io::Write;
use std::net;
use std::net::ToSocketAddrs;
use std::time;
use clap;
use get_if_addrs;
use hostname;
use log::{log,error,debug};
use env_logger;

use itertools::Itertools;

use tabwriter::TabWriter;

// Group of hosts and ports to attempt connections
#[derive(Debug)]
struct HostsPorts {
    hostnames: Vec<String>,
    ports: Vec<u16>
}

// Hostnames and results of an DNS/host lookup
#[derive(Clone, Debug)]
struct HostLookup {
    hostname: String,
    ip: Option<net::IpAddr>
}

impl std::fmt::Display for HostLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            Some(ip) => write!(f, "{} {}", self.hostname, ip),
            None => write!(f, "{}", self.hostname)
        }
    }
}

#[derive(Debug)]
enum ConnectResult {
    Open {
        local: net::SocketAddr, 
        peer: net::SocketAddr
    },
    Closed,
    Filtered,
    OtherIoError(io::Error)
}

impl From<io::Result<net::TcpStream>> for ConnectResult {
    fn from(result: io::Result<net::TcpStream>) -> ConnectResult {
        match result {
            Ok(stream) => {
                let local = stream.local_addr();
                let peer = stream.peer_addr();
                ConnectResult::Open {
                    local: local.expect("TCP stream should have local IP"),
                    peer: peer.expect("TCP stream should have peer IP")
                }
            },
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::TimedOut => ConnectResult::Filtered,
                    io::ErrorKind::ConnectionRefused => ConnectResult::Closed,
                    _ => ConnectResult::OtherIoError(e)
                }
            }
        }
    }
}

impl std::fmt::Display for ConnectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectResult::Open {..} => write!(f, "Open"),
            ConnectResult::Closed => write!(f, "Closed"),
            ConnectResult::Filtered => write!(f, "Filtered"),
            ConnectResult::OtherIoError(e) => write!(f, "Error: {}", e)
        }
    }
}

#[derive(Debug)]
struct ReportItem {
    local: HostLookup,
    peer: HostLookup,
    port: u16,
    result: ConnectResult
}

impl ReportItem {
    fn from_connect_result(
        local: HostLookup,
        peer: HostLookup,
        port: u16,
        result: ConnectResult) -> ReportItem {
        match result {
            // for open connections, replace initial guesses
            // with actual ips used
            ConnectResult::Open {
                local: local_addr,
                peer: peer_addr
            } => ReportItem {
                local: HostLookup { hostname: local.hostname, ip: Some(local_addr.ip()) },
                peer: HostLookup { hostname: peer.hostname, ip: Some(peer_addr.ip()) },
                port, result
            },
            _  => ReportItem {
                local: HostLookup { hostname: local.hostname, ip: None },
                peer, port, result
            }
        }
    }

    // especially for errors during host lookup
    fn from_io_error(
        local_host_lookup: HostLookup,
        peer_hostname: &str,
        port: u16,
        err: io::Error) -> ReportItem {
        ReportItem {
            local: local_host_lookup.clone(),
            peer: HostLookup {
                hostname: peer_hostname.to_string(),
                ip: None
            },
            port,
            result: ConnectResult::OtherIoError(err)
        }
    }

    fn header<W: Write>(tw: &mut TabWriter<W>) {
        let r = writeln!(tw, "Local\tPeer\tPort\tResult");
        if let Err(e) = r {
            error!("Error writing header: {}", e);
        }
    }

    fn println<W: Write>(&self, tw: &mut TabWriter<W>) {
        let r = writeln!(tw, "{}\t{}\t:{}\t{}",
            self.local, self.peer, self.port, self.result);
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
            get_if_addrs::IfAddr::V6(i) => i.broadcast.is_some()
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
fn group_dest_args(matches: &clap::ArgMatches<'_>) -> Vec<HostsPorts> {
    let dest_matches = matches.values_of_lossy("dest").unwrap_or_else(|| vec![]);
    let mut dest_args = dest_matches.iter();
    let mut dests: Vec<HostsPorts> = vec![];
    loop {
        let dest_hosts = dest_args
            .take_while_ref(|s| !s.starts_with(':'))
            .cloned().collect_vec();
        if dest_hosts.is_empty() { break; }
        let mut dest_ports = dest_args.take_while_ref(|s|  s.starts_with(':'))
            .map(|s| -> Option<u16> {
                let s1 = s.trim_start_matches(':');
                let parsed = s1.parse::<u16>();
                match parsed {
                    Ok(x) => Some(x),
                    Err(e) => {
                        // this should be a fatal error, need to figure out how to verify
                        error!("Couldn't parse port number, ignoring {0}, {1}", s, e);
                        None
                    }
                }
            })
            .flat_map(|s| s)
            .collect_vec();
        if dest_ports.is_empty() {
            // default ports
            dest_ports.extend([ 80, 443 ].iter());
        }
        dests.push(HostsPorts { hostnames: dest_hosts, ports: dest_ports });
    }
    dests
}

fn report_host_port(local_host_lookup: &HostLookup,
     peer_info: &HostLookup,  sock_addr: &net::SocketAddr, port: u16) -> Result<Vec<ReportItem>, io::Error>
{
    let socket_addrs = (sock_addr.ip(), port).to_socket_addrs()?;
    let report = socket_addrs.map(|s| {
        let t = net::TcpStream::connect_timeout(&s, time::Duration::from_millis(3000));
        debug!("tcp connect addr {:?} returned {:?}", s, t);
        ReportItem::from_connect_result(
            local_host_lookup.clone(),
            peer_info.clone(),
            port,
            t.into()
        )
    }).collect();
    Ok(report)
}

fn report_host(local_host_lookup: &HostLookup,
    host: &str, lookup_port: u16, ports: &[u16]) -> Result<Vec<ReportItem>,io::Error>
{
    let socket_addrs = (host, lookup_port).to_socket_addrs()?;
    let host_report: Vec<_> = socket_addrs.map(|s|{
        let peer_info = HostLookup {
            hostname: host.to_string(),
            ip: Some(s.ip())
        };

        let socket_addr_report: Vec<ReportItem> = ports.iter().map(|port| {
            report_host_port(local_host_lookup, &peer_info, &s, *port)
                .unwrap_or_else(|err| vec![
                    ReportItem::from_io_error(
                        local_host_lookup.clone(),
                         &peer_info.hostname,
                        *port, err)
                    ])
        }).flatten().collect();
        socket_addr_report
    }).flatten().collect();
    Ok(host_report)
}

fn report_hosts_ports(local_host_lookup: &HostLookup, hosts_ports: &HostsPorts)
    -> Vec<ReportItem> {
    // assume that any port will result in the same lookup,
    // so use the first port just to find the dest ip
    let lookup_port = hosts_ports.ports.get(0).map_or(443, |p| *p);
    hosts_ports.hostnames.iter().map(|host| {
        report_host(local_host_lookup, host, lookup_port, &hosts_ports.ports)
            .unwrap_or_else(|err| vec![
                ReportItem::from_io_error(
                local_host_lookup.clone(),
                &host, lookup_port, err)
            ])
    }).flatten().collect()
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
                interfaces.into_iter()
                    .map(|i| {
                        debug!("interface {:?}", i);
                        i
                    })
                    .filter(|i| !i.is_loopback() && i.has_broadcast())
                    .map(|i| HostLookup {
                        hostname: src_hostname.into(),
                        ip: Some(i.ip()),
                    })
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
    let appmatches = clap::App::new("ackreport")
        .version("0.0")
        .author("Joel Roller <roller@gmail.com>")
        .arg(clap::Arg::with_name("dest")
             .help("Destination hostnames and :ports")
             .multiple(true)
             .required(true))
        .arg(clap::Arg::with_name("interfaces")
            .help("Show interfaces")
            .short("i")
            .long("interfaces")
            .takes_value(false))
        .get_matches();

    let dests = group_dest_args(&appmatches);
    let src_hostname = get_hostname();
    let mut tw = TabWriter::new(io::stdout());

    if appmatches.is_present("interfaces") {
        report_interfaces(&mut tw, &src_hostname)
    }

    let local_host_fallback = HostLookup {
        hostname: src_hostname.clone(),
        ip: None
    };

    let report = dests.iter().map(
        |x| report_hosts_ports(&local_host_fallback, &x)
    ).flatten();

    ReportItem::header(&mut tw);
    for item in report {
        item.println(&mut tw);
    }

    if let Err(e) = tw.flush() {
        error!("Couldn't flush tab writer: {}", e);
    }
}

