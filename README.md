# ackreport

Attempt TCP connections and report on open ports.
Compared to [nmap](https://nmap.org/), ackreport has no features but may be easier to install.
It is meant to be a slightly more civilized "telnet test".

## Usage

```
ackreport 0.1.0

USAGE:
    ackreport [FLAGS] [OPTIONS] <dest>...

FLAGS:
    -h, --help          Prints help information
    -i, --interfaces    Show interfaces
    -V, --version       Prints version information

OPTIONS:
        --threads <threads>    Parallel connection attempts (default 10) [env: RAYON_NUM_THREADS=]

ARGS:
    <dest>...    Destination hostnames and :ports
```

## Example

```
$ ackreport slashdot.org freshmeat.net :25 :80 :443
```

```
Local                 Peer                         Port  Result
abc101                slashdot.org 216.105.38.15   :25   Filtered
abc101 192.168.1.101  slashdot.org 216.105.38.15   :80   Open
abc101 192.168.1.101  slashdot.org 216.105.38.15   :443  Open
abc101                freshmeat.net 216.105.38.10  :25   Filtered
abc101 192.168.1.101  freshmeat.net 216.105.38.10  :80   Open
abc101                freshmeat.net 216.105.38.10  :443  Closed
```

No local IP is reported for connections that are not ACKed, the `--interfaces` option
is provided for a guess at the local IP.

```
$ ackreport -i freshmeat.net :25
```

```
Local Interfaces
abc101 192.168.1.101
Local   Peer                         Port  Result
abc101  freshmeat.net 216.105.38.10  :25   Filtered
```

## Installation

[rustup](https://www.rust-lang.org/learn/get-started) and `cargo build --release`.
Copy the binary to your path.

## License
[MIT](https://choosealicense.com/licenses/mit/)