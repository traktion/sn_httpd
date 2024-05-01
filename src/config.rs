use std::env::args;
use std::net::SocketAddr;
use anyhow::anyhow;
use log::info;
use multiaddr::Multiaddr;

#[derive(Clone)]
pub struct AppConfig {
    pub bind_socket_addr: SocketAddr,
    pub static_dir: String,
    pub network_peer_addr: Multiaddr,
    pub dns_register: String
}

impl AppConfig {
    pub fn read_args() -> color_eyre::Result<AppConfig> {
        // Skip executable name form args
        let mut args_received = args();
        args_received.next();

        // Read the network contact socket address from first arg passed
        let bind_addr = args_received
            .next().expect("No bind address provided");
        let bind_socket_addr: SocketAddr = bind_addr
            .parse()
            .map_err(|err| anyhow!("Invalid bind socket address: {}", err)).unwrap();
        info!("Bind address [{}]", bind_socket_addr);

        // Read the network contact socket address from second arg passed
        let static_dir = args_received
            .next().expect("No static dir provided");
        info!("Static file directory: [{}]", static_dir);

        // Read the network contact peer multiaddr from third arg passed
        let network_contact = args_received
            .next().expect("No Safe network peer address provided");
        let network_peer_addr: Multiaddr = network_contact
            .parse::<Multiaddr>()
            .map_err(|err| anyhow!("Invalid Safe network peer address: {}", err)).unwrap();
        info!("Safe network to be contacted: [{}]", network_peer_addr);

        // Read the network contact socket address from second arg passed
        let dns_register = args_received
            .next().expect("No DNS register provided");
        info!("DNS register: [{}]", dns_register);

        Ok(AppConfig {
            bind_socket_addr,
            static_dir,
            network_peer_addr,
            dns_register
        })
    }
}