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
Note that the results may differ from web browsers or security best practices.

```
$ ackreport --tls badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

```
exec: cargo run --release -- --tls badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443
```

The `--tls` option uses OS certificate roots.
Using `--tls-moz-roots` instead will use the mozilla certificate bundle statically compiled into the binary.
The [rustls-native-certs README](https://github.com/ctz/rustls-native-certs/blob/main/README.md) has some Pros and Cons of each.

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release` or download from github releases page.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)
