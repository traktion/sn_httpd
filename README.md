# sn_httpd

## Background

The Safe Network is a distributed data network where both mutable and immutable data can be stored.
The network can be accessed via any client application, which is currently limited to a CLI. While
a browser is under development, sn_httpd tries to bridge the gap between the old HTTP driven internet
and the brave new world of the Safe Network.

## Features

sn_httpd currently provides the following:

- Static hosting of files stored in a static directory. These could also be javascript files, such as
an Anguler SPA.
- A gateway from /blob/<TrimmedSafeURL> to safe://<TrimmedSafeURL>, where TrimmedSafeURL is a SafeURL
without the 'safe://' prefix.
- Native integration of the sn_client libraries into Actix web framework. These are both written in
Rust to provide smooth integration.
  
## TODO

Many, many things! This is an initial prototype, with no emphasis on performance beyond naive caching
rules. Access to Safe Network is purely on a read only basis too.

## Build Instructions

### Linux Target

It is recommended that the MUSL target is used to prevent runtime dependency issues.

On Ubuntu:

`sudo apt-get install musl-tools`

Then add target:

`rustup target add x86_64-unknown-linux-musl`

Then build release:

`cargo build --release --target x86_64-unknown-linux-musl`

### Windows Target

On Ubuntu:

`sudo apt-get install mingw-w64`

Then add target:

`rustup target add x86_64-pc-windows-gnu`

Then build release:

`cargo build --release --target x86_64-pc-windows-gnu`

### Run instructions

`cargo run 127.0.0.1:8080 static /ip4/127.0.0.1/udp/59676/quic-v1/p2p/12D3KooWFyrDyLrzfejWeA2YmEWaST7oS7mfftuutTvuJwQ9mcpT`

Where `/ip4/127.0.0.1/udp/59676/quic-v1/p2p/12D3KooWFyrDyLrzfejWeA2YmEWaST7oS7mfftuutTvuJwQ9mcpT` is a peer address.