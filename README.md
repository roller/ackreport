# ackreport

ackreport is a simple tool to test TCP and TLS network and socket behavior.
It is meant to be a more civilized "telnet test".

## Usage

ackreport takes a list of destinations: hostnames and :ports.
Arguments starting with `:` are interpreted as port numbers.
For hostnames that return multiple IP addresses, all addresses will be checked.

```
ackreport 0.3.0

USAGE:
    ackreport [FLAGS] [OPTIONS] <dest>...

FLAGS:
    -h, --help       Prints help information
        --tls        Attempt TLS handshake with OS cert roots
        --tls-moz    Attempt TLS handshake with mozilla cert roots
    -V, --version    Prints version information

OPTIONS:
        --threads <threads>    Parallel connection attempts (default 10) [env: RAYON_NUM_THREADS=]
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
abc101                slashdot.org 204.68.111.106  :25   7s    Filtered
abc101 192.168.1.101  slashdot.org 204.68.111.106  :80   66ms  Open
abc101 192.168.1.101  slashdot.org 204.68.111.106  :443  66ms  Open
abc101                freshmeat.net 216.105.38.10  :25   7s    Filtered
abc101 192.168.1.101  freshmeat.net 216.105.38.10  :80   62ms  Open
abc101                freshmeat.net 216.105.38.10  :443  61ms  Closed
```

ackreport can attempt to negotiate a TLS connection.
Here's some badssl examples to demonstrate the output format.
Note that the results may differ from web browsers or security best practices.

```
$ ackreport --tls badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

```
Local                 Peer                                      Port  Time   Result
abc101 192.168.1.101  badssl.com 104.154.89.105                 :80   127ms  OpenNoTLS
abc101                badssl.com 104.154.89.105                 :99   7s     Filtered
abc101 192.168.1.101  no-common-name.badssl.com 104.154.89.105  :443  58ms   invalid certificate: CertExpired
abc101 192.168.1.101  wrong.host.badssl.com 104.154.89.105      :443  129ms  invalid certificate: CertNotValidForName
abc101 192.168.1.101  self-signed.badssl.com 104.154.89.105     :443  53ms   invalid certificate: UnknownIssuer
abc101 192.168.1.101  revoked.badssl.com 104.154.89.105         :443  129ms  TLSv1_2
abc101 192.168.1.101  1000-sans.badssl.com 104.154.89.105       :443  129ms  TLSv1_2
abc101 192.168.1.101  ecc384.badssl.com 104.154.89.105          :443  159ms  TLSv1_2
abc101 192.168.1.101  rsa8192.badssl.com 104.154.89.105         :443  149ms  TLSv1_2
abc101 192.168.1.101  mitm-software.badssl.com 104.154.89.105   :443  134ms  invalid certificate: UnknownIssuer
```

The `--tls` option uses OS certificate roots.
Using `--tls-moz` instead will use the mozilla certificate bundle statically compiled into the binary.
The [rustls-native-certs README](https://github.com/ctz/rustls-native-certs/blob/main/README.md) has some Pros and Cons of each.

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release` or download from github releases page.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)
