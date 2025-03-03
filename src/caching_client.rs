use std::{env, fs};
use std::fs::File;
use std::io::{Read, Write};
use autonomi::Client;
use autonomi::client::files::archive_public::{ArchiveAddress, PublicArchive};
use autonomi::client::GetError;
use autonomi::data::DataAddress;
use bytes::Bytes;
use log::{debug, info};
use xor_name::XorName;
use crate::archive_helper::ArchiveHelper;

#[derive(Clone)]
pub struct CachingClient {
    client: Client,
    cache_dir: String,
}

impl CachingClient {

    pub fn new(client: Client) -> Self {
        let cache_dir = env::temp_dir().to_str().unwrap().to_owned() + "/anttp/cache/";
        CachingClient::create_tmp_dir(cache_dir.clone());
        Self {
            client, cache_dir,
        }
    }
    
    fn create_tmp_dir(cache_dir: String) {
        if !fs::exists(cache_dir.clone()).unwrap() {
            fs::create_dir_all(cache_dir.clone()).unwrap_or_default()
        }
    }

    /// Fetch an archive from the network
    pub async fn archive_get_public(&self, archive_address: ArchiveAddress) -> Result<PublicArchive, GetError> {
        let cached_data = self.read_file(archive_address).await;
        if !cached_data.is_empty() {
            Ok(PublicArchive::from_bytes(cached_data)?)
        } else {
            let data = self.client.data_get_public(&archive_address).await?;
            self.write_file(archive_address, data.to_vec()).await;
            Ok(PublicArchive::from_bytes(data)?)
        }
    }

    pub async fn data_get_public(&self, addr: &DataAddress) -> Result<Bytes, GetError> {
        let cached_data = self.read_file(*addr).await;
        if !cached_data.is_empty() {
            debug!("getting cached data for {:?} from local storage", addr);
            Ok(cached_data)
        } else {
            debug!("getting non-cached data for {:?} from network", addr);
            let data = self.client.data_get_public(addr).await?;
            self.write_file(*addr, data.to_vec()).await;
            Ok(data)
        }
    }

    pub async fn write_file(&self, archive_address: ArchiveAddress, data: Vec<u8>) {
        let path_string = self.cache_dir.clone() + format!("{:x}", archive_address.xorname()).as_str();
        let mut file = File::create(path_string).unwrap();
        file.write_all(data.as_slice()).unwrap();
    }

    pub async fn read_file(&self, archive_address: ArchiveAddress) -> Bytes {
        let path_string = self.cache_dir.clone() + format!("{:x}", archive_address.xorname()).as_str();
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

    pub async fn config_get_public(&self, archive: PublicArchive, archive_address_xorname: XorName) -> color_eyre::Result<crate::app_config::AppConfig> {
        let path_str = "app-conf.json";
        let mut path_parts = Vec::<String>::new();
        path_parts.push("ignore".to_string());
        path_parts.push(path_str.to_string());
        match ArchiveHelper::new(archive).resolve_data_addr(path_parts) {
            Ok(data_address) => {
                info!("Downloading app-config [{}] with addr [{}] from archive [{}]", path_str, format!("{:x}", data_address.xorname()), format!("{:x}", archive_address_xorname));
                match self.data_get_public(&data_address).await {
                    Ok(data) => {
                        let json = String::from_utf8(data.to_vec()).unwrap_or(String::new());
                        debug!("json [{}]", json);
                        let config: crate::app_config::AppConfig = serde_json::from_str(&json.as_str())
                            .unwrap_or(crate::app_config::AppConfig::default());

                        Ok(config)
                    }
                    Err(_e) => {
                        Ok(crate::app_config::AppConfig::default())
                    }
                }
            }
            Err(_e) => Ok(crate::app_config::AppConfig::default())
        }
    }
}