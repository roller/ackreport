
# Test scenario against badssl
badssl:
    RUST_LOG=info cargo run --release -- --threads 1 --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com 10000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443

# Test scenario using only localhost
local:
    RUST_LOG=info cargo run --release -- localhost

# Test scenario with short timeout expected to error
timeout:
    RUST_LOG=info cargo run --release -- --threads 1 --tls --timeout 30ms badssl.com :80 badssl.com :99 no-common-name.badssl.com :443

# Overwrite README.md using README.template.md script
readme:
    #!/usr/bin/perl
    open(my $fh, "<", "README.template.md") or die "< template $!";
    open(my $readme, ">", "README.md") or die "> readme $!";
    my $host = `hostname`;
    chomp $host;
    select $readme;

    while (<$fh>) {
        if (/^exec: (.*)$/) {
            $out = `$1`;
            $out =~ s/^Local.*?(?=  [^ ])/Local               /gm;
            $out =~        s/^$host \d\S*/abc101 192.168.1.101/gm;
            $out =~  s/^$host.*? (?=[^ ])/abc101                /gm;
            print $out;
        } else {
            print $_;
        }
    }

# build a docker image
docker:
    docker build .

# build release binaries in WSL
release_bin_wsl:
    #!/bin/bash
    # This is run on a Windows WSL environment
    # Rename binaries to include toolchain and version
    set -xe
    version=$(cargo run --release -- --version | awk '{ print $2 }')

    # linux
    toolchain=x86_64-unknown-linux-gnu
    cargo +stable-$toolchain build --release
    strip target/release/ackreport
    cp target/release/ackreport{,-$toolchain-$version}

    # windows, build gnu to avoid msvcrt dep
    toolchain=x86_64-pc-windows-gnu
    cargo.exe +stable-$toolchain build --release
    strip.exe target/release/ackreport
    cp target/release/ackreport{,-$toolchain-$version}.exe

# update readme and binaries
release: release_bin_wsl readme
