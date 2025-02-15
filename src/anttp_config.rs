use std::env::args;
use std::net::SocketAddr;
use anyhow::anyhow;
use log::info;

#[derive(Clone)]
pub struct AntTpConfig {
    pub bind_socket_addr: SocketAddr,
    pub static_dir: String
}

impl AntTpConfig {
    pub fn read_args() -> color_eyre::Result<AntTpConfig> {
        // Skip executable name form args
        let mut args_received = args();
        args_received.next();

        // Read the network contact socket address from first arg passed
        let bind_addr = args_received.next().unwrap_or_else(|| "0.0.0.0:8080".to_string());
        let bind_socket_addr: SocketAddr = bind_addr
            .parse()
            .map_err(|err| anyhow!("Invalid bind socket address: {}", err)).unwrap();
        info!("Bind address [{}]", bind_socket_addr);

        // Read the network contact socket address from second arg passed
        let static_dir = args_received.next().unwrap_or_else(|| "static".to_string());
        info!("Static file directory: [{}]", static_dir);

        Ok(AntTpConfig {
            bind_socket_addr,
            static_dir
        })
    }
}