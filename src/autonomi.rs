use std::path::PathBuf;
use ant_bootstrap::PeersArgs;
use autonomi::Client;
use bls::SecretKey;
use color_eyre::eyre::Context;
use color_eyre::Help;
use log::info;
use multiaddr::Multiaddr;
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

    //pub async fn init(&self) -> (Client, FilesApi) {
    pub async fn init(&self) -> Client {
        // initialise safe network connection and files api
        let peers =  Self::get_peers(PeersArgs::default()).await.unwrap();
        Client::init_with_peers(peers).await.expect("Failed to connect to Autonomi Network")
    }

    pub async fn get_peers(peers: PeersArgs) -> color_eyre::Result<Vec<Multiaddr>> {
        peers.get_addrs(None, Some(100)).await
            .wrap_err("Please provide valid Network peers to connect to")
            .with_suggestion(|| format!("make sure you've provided network peers using the --peers option or the ANT_PEERS_ENV env var"))
            .with_suggestion(|| "a peer address looks like this: /ip4/42.42.42.42/udp/4242/quic-v1/p2p/B64nodePeerIDvdjb3FAJF4ks3moreBase64CharsHere")
    }

    fn get_client_secret_key(&self, root_dir: &PathBuf) -> color_eyre::Result<SecretKey> {
        // note: this was pulled directly from sn_cli
        // create the root directory if it doesn't exist
        std::fs::create_dir_all(root_dir)?;
        let key_path = root_dir.join(CLIENT_KEY);
        let secret_key = if key_path.is_file() {
            info!("Client key found. Loading from file...");
            let secret_hex_string = std::fs::read_to_string(key_path)?;
            SecretKey::from_hex(secret_hex_string.as_str())?
            //bls_secret_from_hex(secret_hex_bytes)?
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