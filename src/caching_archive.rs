use std::fs::File;
use std::io::{Read, Write};
use autonomi::Client;
use autonomi::client::data::{GetError};
use autonomi::client::files::archive_public::{ArchiveAddr, PublicArchive};
use bytes::Bytes;

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
            let data = self.client.data_get_public(addr).await?;
            self.write_file(addr, data.to_vec()).await;
            Ok(PublicArchive::from_bytes(data)?)
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
                let mut contents = String::new();
                Bytes::from("")
            }
        }
    }
}