# sn_httpd

## Background

Autonomi (a.k.a. Safe Network) is a distributed data network where both mutable and immutable data can be stored. It can
considered as a best of class web3 experience.

sn_httpd is a HTTP service which serves data from Autonomi over conventional HTTP connections. This allows regular
web browsers (and other apps) to retrieve data from Autonomi without needing any client libraries, CLIs, etc.

Users can either spin up a local sn_httpd service or deploy one to a public environment. This enables developers to
integrate with Autonomi in a more conventional way and gives end users a conventional browsing experience.

## Features

`sn_httpd` currently provides the following:

- Data retrieval from Autonomi using `/safe/[XOR_ADDRESS]`. Data is streamed directly from Autonomi to reduce
  latency and allows clients to immediately consume the data.
- Data retrieval from Autonomic using file maps for human readable naming `/[MAP_XOR_ADDRESS]/[MY_FILE_NAME]`. Enables
  regular static sites to be uploaded/browsed (once a fileMap is provided - see [example-config](app-config.json).
- Routing from URLs to specific `[XOR_ADDRESS]` or `[FILE_NAME]`. Enables SPA (single page apps) such as Angular or
  React to be hosted (once a routeMap is provided - see [example-config](app-config.json)
- Experimental support for DNS style lookups, using registers to provide `/[DNS_NAME]/[MY_FILE_NAME]`. More to follow!
- Hosting of conventional static files using `/static`.
- Native integration of the `sn_client` libraries into Actix web framework. These are both written in Rust to provide
  smooth integration. As Actix is core to `sn_httpd`, it can be extended for specific use cases easily. 
  
## TODO

- Built-in accounting features to allow hosts fund bandwidth usage via Autonomi Network Tokens. While Autonomi doesn't
  have any bandwidth usage fees, traffic too/from `sn_httpd` may be subject to charges by your hosting company. This
  will allow self-service for site authors to publish their site on your `sn_httpd` instance - the backend data is
  always on Autonomi, irrespective of where `sn_httpd` is hosted!
- Refactoring, performance, stability - `sn_httpd` is highly experimental and should only be used by the adventurous!

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

### ARM Target

On Ubuntu:

`sudo apt install gcc make gcc-arm* gcc-aarch64* binutils-arm* binutils-aarch64* pkg-config libssl-dev`

Then add target:

`rustup target add arm-unknown-linux-musleabi`
`rustup target add gcc-arm-linux-gnueabi`

Then update the environment:

`export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc`
`export CC=aarch64-linux-gnu-gcc`

Then build release:

`cargo build --release --target aarch64-unknown-linux-musl`

### Run instructions

`cargo run 127.0.0.1:8080 static /ip4/142.93.46.42/udp/43338/quic-v1/p2p/12D3KooWSaCWsF2qLULtKTtjJPYpzCKn3X3aY19WdznPB5jUfmt3 6d70bf50aec7ebb0f1b9ff5a98e2be2f9deb2017515a28d6aea0c6f80a9f44ddaf480334bbff0cd23302b386bfc071a51d132e8e13055701a94211eaada0b6b4c37a94f8adc1e96be1aa1f149b7faffa`

Where:

- `/ip4/142.93.46.42/udp/43338/quic-v1/p2p/12D3KooWSaCWsF2qLULtKTtjJPYpzCKn3X3aY19WdznPB5jUfmt3` is a peer address.
- `6d70bf50aec7ebb0f1b9ff5a98e2be2f9deb2017515a28d6aea0c6f80a9f44ddaf480334bbff0cd23302b386bfc071a51d132e8e13055701a94211eaada0b6b4c37a94f8adc1e96be1aa1f149b7faffa` is a `DNS_REGISTER`.

### App Configuration

See [example-config](app-config.json) for customising how your web site/app behaves on `sn_httpd`.

The config should be uploaded to Autonomi and the corresponding `XOR_ADDRESS` can then be used as the site root,
e.g. `/[XOR_ADDRESS]/[OTHER_FILES]`. The config can have any file name as only the XOR address is important to `sn_httpd`.

Given each change to the App Configuration will result in a different XOR address, a form of DNS can be used to map a
name to an XOR address.

At the time of writing, only a single name can be referenced per `sn_httpd` instance. This will change once the register
interface has been finalised, to allow register history to be retrieved.

To create a site register (for the specific site/app):

`safe register create [SITE_REGISTER]`

To point the register at your App Configuration:

`safe register edit [SITE_REGISTER] [CONFIG_XOR_ADDRESS]`

When the App Configuration is updated, repeat the above with its new XOR address.

To create a DNS register for the `sn_httpd` instance, use the CLI:

`safe register create [DNS_REGISTER]`

To add/edit a name, edit the register to append the site register:

`safe register edit [REGISTER_ADDRESS] "[APP_NAME],[APP_ADDRESS]"`

Once completed, `/[APP_NAME]` will resolve to the App Configuration and any path after this point will reference
the App Configuration, e.g. with `/myapp/myfile`, `myfile` can be in the `dataMap` and route to an XOR address.

### Example site - IMIM!

I maintain a blog using the [IMIM](https://github.com/traktion/i-am-immutable-client) platform, which allows authors 
to write Markup text files and publish them on Autonomi. Using `sn_httpd`, these blogs can be viewed anywhere that an
instance is running.

Why not take a look and start your own immutable blog today?