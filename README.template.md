# ackreport

Attempt TCP connections and report on open ports.
Compared to [nmap](https://nmap.org/), ackreport has no features but may be easier to install.
It is meant to be a slightly more civilized "telnet test".

## Usage

ackreport takes a list of destinations: hostnames and :ports.
Arguments starting with : are interpretted as port numbers.
For hostnames that return multiple IP addresses, all addresses will be checked.

```
exec: cargo run --release -- --help
```

## Example

```
$ ackreport slashdot.org freshmeat.net :25 :80 :443
```

```
exec: cargo run --release -- slashdot.org freshmeat.net :25 :80 :443
```

No local IP is reported for connections that are not ACKed, the `--interfaces` option
is provided for a guess at the local IP.

```
$ ackreport -i freshmeat.net :25
```

```
exec: cargo run --release -- -i freshmeat.net :25
```

ackreport can attempt to negotiate a TLS connection.
Here's some badssl examples to demonstrate the output format.
Note that the results may differ from best practices or web browsers.

```
$ ackreport --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

```
exec: cargo run --release -- --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release`.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## TODO

- select native or moz roots
- provide more info with certificate chain subjects, expire dates

