# ackreport

Attempt TCP connections and report on open ports.
Compared to [nmap](https://nmap.org/), ackreport has no features but may be easier to install.
It is meant to be a slightly more civilized "telnet test".

## Usage

ackreport takes a list of destinations: hostnames and :ports.
Arguments starting with : are interpretted as port numbers.
For hostnames that return multiple IP addresses, all addresses will be checked.

```
ackreport 0.2.1

USAGE:
    ackreport [FLAGS] [OPTIONS] <dest>...

FLAGS:
    -h, --help          Prints help information
    -i, --interfaces    Show interfaces
        --tls           Attempt TLS negotiation
    -V, --version       Prints version information

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
Local                 Peer                         Port  Time   Result
abc101                slashdot.org 13.32.212.82    :25   7s     Filtered
abc101 192.168.1.101  slashdot.org 13.32.212.82    :80   589µs  Open
abc101 192.168.1.101  slashdot.org 13.32.212.82    :443  626µs  Open
abc101                slashdot.org 13.32.212.71    :25   7s     Filtered
abc101 192.168.1.101  slashdot.org 13.32.212.71    :80   605µs  Open
abc101 192.168.1.101  slashdot.org 13.32.212.71    :443  660µs  Open
abc101                slashdot.org 13.32.212.125   :25   7s     Filtered
abc101 192.168.1.101  slashdot.org 13.32.212.125   :80   629µs  Open
abc101 192.168.1.101  slashdot.org 13.32.212.125   :443  635µs  Open
abc101                slashdot.org 13.32.212.21    :25   7s     Filtered
abc101 192.168.1.101  slashdot.org 13.32.212.21    :80   597µs  Open
abc101 192.168.1.101  slashdot.org 13.32.212.21    :443  648µs  Open
abc101                freshmeat.net 216.105.38.10  :25   53ms   Closed
abc101 192.168.1.101  freshmeat.net 216.105.38.10  :80   53ms   Open
abc101                freshmeat.net 216.105.38.10  :443  53ms   Closed
```

No local IP is reported for connections that are not ACKed, the `--interfaces` option
is provided for a guess at the local IP.

```
$ ackreport -i freshmeat.net :25
```

```
Local Interfaces
abc101 192.168.1.101
abc101 192.168.1.101
Local                 Peer                         Port  Time  Result
abc101                freshmeat.net 216.105.38.10  :25   55ms  Closed
```

ackreport can attempt to negotiate a TLS connection.
Here's some badssl examples to demonstrate the output format.
Note that the results may differ from best practices or web browsers.

```
$ ackreport --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

```
Local                 Peer                                      Port  Time   Result
abc101 192.168.1.101  badssl.com 104.154.89.105                 :80   47ms   IncompleteHandshake
abc101                badssl.com 104.154.89.105                 :99   1s     Filtered
abc101 192.168.1.101  no-common-name.badssl.com 104.154.89.105  :443  48ms   invalid certificate: CertExpired
abc101 192.168.1.101  wrong.host.badssl.com 104.154.89.105      :443  118ms  invalid certificate: CertNotValidForName
abc101 192.168.1.101  self-signed.badssl.com 104.154.89.105     :443  51ms   invalid certificate: UnknownIssuer
abc101 192.168.1.101  revoked.badssl.com 104.154.89.105         :443  118ms  TLSv1_2
abc101 192.168.1.101  1000-sans.badssl.com 104.154.89.105       :443  119ms  TLSv1_2
abc101 192.168.1.101  ecc384.badssl.com 104.154.89.105          :443  118ms  TLSv1_2
abc101 192.168.1.101  rsa8192.badssl.com 104.154.89.105         :443  141ms  TLSv1_2
abc101 192.168.1.101  mitm-software.badssl.com 104.154.89.105   :443  53ms   invalid certificate: CertExpired
```

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release`.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## TODO

- select native or moz roots
- provide more info with certificate chain subjects, expire dates

