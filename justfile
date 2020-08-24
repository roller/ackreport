
badssl:
    RUST_LOG=info cargo run -- --threads 1 --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com 10000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443

local:
    RUST_LOG=info cargo run -- localhost

timeout:
    RUST_LOG=info cargo run -- --threads 1 --tls --timeout 30ms badssl.com :80 badssl.com :99 no-common-name.badssl.com :443
