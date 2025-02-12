# AntTP

## Background

Autonomi (a.k.a. Safe Network) is a distributed data network where both mutable and immutable data can be stored. It can
considered as a best of class web3 experience.

AntTP is a HTTP service which serves data from Autonomi over conventional HTTP connections. This allows regular
web browsers (and other apps) to retrieve data from Autonomi without needing any client libraries, CLIs, etc.

Users can either spin up a local antTP service or deploy one to a public environment. This enables developers to
integrate with Autonomi in a more conventional way and gives end users a conventional browsing experience.

AntTP was formally known as sn_httpd.

## Features

`antTP` currently provides the following:

- Data retrieval from Autonomic using archives for human readable naming `/[ARCHIVE_XOR_ADDRESS]/[MY_FILE_NAME]`. Enables
  regular static sites to be uploaded as an archive, with files browsed by file name.
- Proxy server to allow `http://[ARCHIVE_XOR_ADDRESS]/[MY_FILE_NAME]` to be resolved. Allows
  sites to pivot from a 'root' directory and a smoother user experience.
- Routing from URLs to specific `[XOR_ADDRESS]` or `[FILE_NAME]`. Enables SPA (single page apps) such as Angular or
  React to be hosted (once a routeMap is provided - see [example-config](app-conf.json)
- Native integration of the `autonomi` libraries into Actix web framework. These are both written in Rust to provide
  smooth integration. As Actix is core to `antTP`, it can be extended for specific use cases easily. 
  
## TODO

- Built-in accounting features to allow hosts fund bandwidth usage via Autonomi Network Tokens. While Autonomi doesn't
  have any bandwidth usage fees, traffic too/from `antTP` may be subject to charges by your hosting company. This
  will allow self-service for site authors to publish their site on your `antTP` instance - the backend data is
  always on Autonomi, irrespective of where `antTP` is hosted!
- Refactoring, performance, stability - `antTP` is highly experimental and should only be used by the adventurous!
- Unit testing

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

`cargo run 0.0.0.0:8080 static`

Where:

- `0.0.0.0:8080` (optional, default = `0.0.0.0:8080`) is the IP address and port to listen on.
- `static` (optional, default = `static`) is a directory to host local/static files in.

### Archive Upload

To upload a directory to Autonomi as an archive, do the following:

- `cd your/directory`
- `ant file upload -p -x <directory>`

This command will return information about the uploads and summarise with something like:

`Uploading file: "./1_bYTCL7G4KbcR_Y4rd78OhA.png"
Upload completed in 5.57326318s
Successfully uploaded: ./
At address: 387f61da64d2a4c5d2e02ca34660fa2ac4fa6b3604ed8b67a58a3cba6e8ae787`

The 'At address' is the archive address and you can now reference the uploaded files like:

Via a proxy (to localhost:8080):
`http://a0f6fa2b08e868060fe6e57018e3f73294821feaf3fdcf9cd636ac3d11e7e2ac/BegBlag.mp3` 

Or via direct request:
`http://localhost:8080/a0f6fa2b08e868060fe6e57018e3f73294821feaf3fdcf9cd636ac3d11e7e2ac/BegBlag.mp3`

### App Configuration

See [example-config](app-conf.json) for customising how your web site/app behaves on `antTP`.

The config should be uploaded to Autonomi and the corresponding `XOR_ADDRESS` can then be used as the site root,
e.g. `/[XOR_ADDRESS]/[OTHER_FILES]`. The config can have any file name as only the XOR address is important to `antTP`.

Given each change to the App Configuration will result in a different XOR address, a form of DNS can be used to map a
name to an XOR address.

### Example site - IMIM!

I maintain a blog using the [IMIM](https://github.com/traktion/i-am-immutable-client) platform, which allows authors 
to write Markup text files and publish them on Autonomi. Using `antTP`, these blogs can be viewed anywhere that an
instance is running.

Why not take a look and start your own immutable blog today?
