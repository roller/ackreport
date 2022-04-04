
# Test scenario against badssl
badssl:
    RUST_LOG=info cargo run --release -- --threads 1 --tls --timeout 1s badssl.com :80 badssl.com :99 no-common-name.badssl.com wrong.host.badssl.com self-signed.badssl.com revoked.badssl.com 1000-sans.badssl.com 10000-sans.badssl.com ecc384.badssl.com rsa8192.badssl.com mitm-software.badssl.com :443

# Test scenario using only localhost
local:
    RUST_LOG=info cargo run --release -- localhost

# Test scenario with short timeout expected to error
timeout:
    RUST_LOG=info cargo run --release -- --threads 1 --tls --timeout 30ms badssl.com :80 badssl.com :99 no-common-name.badssl.com :443


# demo tracing tokio-console run
console:
    RUSTFLAGS="--cfg tokio_unstable" cargo run --features tracing -- --timeout 10s --threads 2 www.yahoo.com www.slashdot.org :80 :99 :100 :101 :102 :103 :104 :105 :106 :107 :108 :109 :110

# build release
build_release:
    cargo build --release

# install into ~/.cargo/bin
build_install: build_release
    cp target/release/ackreport ~/.cargo/bin/ackreport

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
            # ugly padding to keep columns aligned
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

# build windows target using cross
cross_build:
    cross build --no-default-features --release --target x86_64-pc-windows-gnu

# build a windows and linux binaries via cross
release_cross:
    #!/bin/bash
    # This is run on a linux environment with cargo install cross
    # Rename binaries to include toolchain and version
    set -xe
    version=$(cargo run --release -- --version | awk '{ print $2 }')
    reldir="target/release-$version"
    mkdir -p "$reldir"

    # linux
    toolchain=x86_64-unknown-linux-gnu
    relpath="$reldir/ackreport-$toolchain-$version"
    cargo +stable-$toolchain build --release
    cp target/release/ackreport "$relpath"
    strip "$relpath"

    # windows, build gnu to avoid msvcrt dep
    toolchain=x86_64-pc-windows-gnu
    relpath="$reldir/ackreport-$toolchain-$version.exe"
    cross build --no-default-features --release --target x86_64-pc-windows-gnu
    cp "target/$toolchain/release/ackreport.exe" "$relpath"
    strip "$relpath"

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

# create tag based on current version
tag_release:
    #!/bin/bash
    version=$(cargo run --release -- --version | awk '{ print $2 }')
    git tag v${version}

# update readme and binaries
release: build_release readme
