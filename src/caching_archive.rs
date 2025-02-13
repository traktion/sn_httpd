use std::fs::File;
use std::io::{Read, Write};
use autonomi::Client;
use autonomi::client::data::{DataAddr};
use autonomi::client::files::archive_public::{ArchiveAddr, PublicArchive};
use autonomi::client::GetError;
use bytes::Bytes;
use log::{debug};

#[derive(Clone)]
pub struct CachingClient {
    client: Client,
}

impl CachingClient {

    pub fn new(client: Client) -> Self {
        Self {
            client,
        }
    }

    /// Fetch an archive from the network
    pub async fn archive_get_public(&self, addr: ArchiveAddr) -> Result<PublicArchive, GetError> {
        let cached_data = self.read_file(addr).await;
        if !cached_data.is_empty() {
            Ok(PublicArchive::from_bytes(cached_data)?)
        } else {
            let data = self.client.data_get_public(addr.as_ref()).await?;
            self.write_file(addr, data.to_vec()).await;
            Ok(PublicArchive::from_bytes(data)?)
        }
    }

    pub async fn data_get_public(&self, addr: DataAddr) -> Result<Bytes, GetError> {
        let cached_data = self.read_file(addr).await;
        if !cached_data.is_empty() {
            debug!("getting cached data for {:?} from local storage", addr);
            Ok(cached_data)
        } else {
            debug!("getting non-cached data for {:?} from network", addr);
            let data = self.client.data_get_public(addr.as_ref()).await?;
            self.write_file(addr, data.to_vec()).await;
            Ok(data)
        }
    }

    pub async fn write_file(&self, addr: ArchiveAddr, data: Vec<u8>) {
        let path_string = "cache/".to_owned() + format!("{:x}", addr).as_str();
        let mut file = File::create(path_string).unwrap();
        file.write_all(data.as_slice()).unwrap();
    }

    pub async fn read_file(&self, addr: ArchiveAddr) -> Bytes {
        let path_string = "cache/".to_owned() + format!("{:x}", addr).as_str();
        match File::open(path_string) {
            Ok(mut file) => {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                Bytes::from(contents.clone())
            },
            Err(_) => {
                Bytes::from("")
            }
        }
    }
}