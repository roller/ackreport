# ackreport

ackreport is a simple tool to test TCP and TLS network and socket behavior.
It is meant to be a more civilized "telnet test".

## Usage

ackreport takes a list of destinations: hostnames and :ports.
Arguments starting with `:` are interpreted as port numbers.
For hostnames that return multiple IP addresses, all addresses will be checked.

```
ackreport 0.4.8

USAGE:
    ackreport [FLAGS] [OPTIONS] <dest>...

FLAGS:
    -h, --help       Prints help information
        --tls        Attempt TLS handshake with OS cert roots
        --tls-moz    Attempt TLS handshake with mozilla cert roots
    -V, --version    Prints version information

OPTIONS:
        --threads <threads>    Parallel connection attempts [default: 10]
    -t, --timeout <timeout>    Connection timeout (eg 10s or 500ms) [default: 7s]

ARGS:
    <dest>...    Destination hostnames and :ports
```

## Example

```
$ ackreport slashdot.org freshmeat.net :25 :80 :443
```

```
Local                 Peer                         Port  Time  Result
abc101                slashdot.org 104.18.29.86    :25   7s    Filtered
abc101 192.168.1.101  slashdot.org 104.18.29.86    :80   35ms  Open
abc101 192.168.1.101  slashdot.org 104.18.29.86    :443  35ms  Open
abc101                slashdot.org 104.18.28.86    :25   7s    Filtered
abc101 192.168.1.101  slashdot.org 104.18.28.86    :80   35ms  Open
abc101 192.168.1.101  slashdot.org 104.18.28.86    :443  35ms  Open
abc101                freshmeat.net 216.105.38.10  :25   7s    Filtered
abc101 192.168.1.101  freshmeat.net 216.105.38.10  :80   75ms  Open
abc101                freshmeat.net 216.105.38.10  :443  75ms  Closed
```

ackreport can attempt to negotiate a TLS connection.
Here's some badssl examples to demonstrate the output format.
Note that the results may differ from web browsers or security best practices.

```
$ ackreport --tls badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

```
Local                 Peer                                      Port  Time   Result
abc101 192.168.1.101  badssl.com 104.154.89.105                 :80   149ms  OpenNoTLS
abc101                badssl.com 104.154.89.105                 :99   7s     Filtered
abc101 192.168.1.101  no-common-name.badssl.com 104.154.89.105  :443  181ms  invalid peer certificate: CertExpired
abc101 192.168.1.101  wrong.host.badssl.com 104.154.89.105      :443  151ms  invalid peer certificate: CertNotValidForName
abc101 192.168.1.101  self-signed.badssl.com 104.154.89.105     :443  152ms  invalid peer certificate: UnknownIssuer
abc101 192.168.1.101  revoked.badssl.com 104.154.89.105         :443  154ms  invalid peer certificate: CertExpired
abc101 192.168.1.101  1000-sans.badssl.com 104.154.89.105       :443  217ms  invalid peer certificate: CertExpired
abc101 192.168.1.101  ecc384.badssl.com 104.154.89.105          :443  218ms  TLSv1_2
abc101 192.168.1.101  rsa8192.badssl.com 104.154.89.105         :443  183ms  TLSv1_2
abc101 192.168.1.101  mitm-software.badssl.com 104.154.89.105   :443  149ms  invalid peer certificate: UnknownIssuer
```

The `--tls` option uses OS certificate roots.
Using `--tls-moz` instead will use the mozilla certificate bundle statically compiled into the binary.
The [rustls-native-certs README](https://github.com/ctz/rustls-native-certs/blob/main/README.md) has some Pros and Cons of each.

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release` or download from github releases page.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)
