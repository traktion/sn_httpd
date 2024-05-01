use std::path::PathBuf;
use log::info;
use multiaddr::Multiaddr;
use sn_client::{Client, ClientEventsBroadcaster, FilesApi};
use sn_client::transfers::bls::SecretKey;
use sn_client::transfers::bls_secret_from_hex;
use sn_peers_acquisition::{get_peers_from_args, PeersArgs};
use crate::CLIENT_KEY;
use crate::config::AppConfig;

#[derive(Clone)]
pub struct Autonomi {
    app_config: AppConfig
}

impl Autonomi {
    pub fn new(app_config: AppConfig) -> Self {
        Self {
            app_config
        }
    }

    pub async fn init(&self) -> (Client, FilesApi) {
        // initialise safe network connection and files api
        let client = self.safe_connect(&self.app_config.network_peer_addr).await.expect("Failed to connect to Safe Network");
        let data_dir_path = self.get_client_data_dir_path().expect("Failed to get client data dir path");
        let files_api = FilesApi::new(client.clone(), data_dir_path);
        (client, files_api)
    }

    async fn safe_connect(&self, peer: &Multiaddr) -> color_eyre::Result<Client> {
        // note: this was pulled directly from sn_cli

        println!("Instantiating a SAFE client...");
        let secret_key = self.get_client_secret_key(&self.get_client_data_dir_path()?)?;

        let peer_args = PeersArgs { first: false, peers: vec![peer.clone()] };
        let bootstrap_peers = get_peers_from_args(peer_args).await?;

        println!(
            "Connecting to the network with {} peers",
            bootstrap_peers.len(),
        );

        let bootstrap_peers = if bootstrap_peers.is_empty() {
            // empty vec is returned if `local-discovery` flag is provided
            None
        } else {
            Some(bootstrap_peers)
        };

        // get the broadcaster as we want to have our own progress bar.
        let broadcaster = ClientEventsBroadcaster::default();

        let result = Client::new(
            secret_key,
            bootstrap_peers,
            None,
            Some(broadcaster),
        ).await?;
        Ok(result)
    }

    fn get_client_secret_key(&self, root_dir: &PathBuf) -> color_eyre::Result<SecretKey> {
        // note: this was pulled directly from sn_cli
        // create the root directory if it doesn't exist
        std::fs::create_dir_all(root_dir)?;
        let key_path = root_dir.join(CLIENT_KEY);
        let secret_key = if key_path.is_file() {
            info!("Client key found. Loading from file...");
            let secret_hex_bytes = std::fs::read(key_path)?;
            bls_secret_from_hex(secret_hex_bytes)?
        } else {
            info!("No key found. Generating a new client key...");
            let secret_key = SecretKey::random();
            std::fs::write(key_path, hex::encode(secret_key.to_bytes()))?;
            secret_key
        };
        Ok(secret_key)
    }

    fn get_client_data_dir_path(&self) -> color_eyre::Result<PathBuf> {
        // note: this was pulled directly from sn_cli
        let mut home_dirs = dirs_next::data_dir().expect("Data directory is obtainable");
        home_dirs.push("safe");
        home_dirs.push("client");
        std::fs::create_dir_all(home_dirs.as_path())?;
        info!("home_dirs.as_path(): {}", home_dirs.to_str().unwrap());
        Ok(home_dirs)
    }
}