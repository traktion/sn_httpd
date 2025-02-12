use ant_bootstrap::PeersArgs;
use autonomi::Client;
use color_eyre::eyre::Context;
use color_eyre::Help;
use multiaddr::Multiaddr;

#[derive(Clone)]
pub struct Autonomi;

impl Autonomi {
    pub fn new() -> Self {
        Self
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
}