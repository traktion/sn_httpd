use std::collections::HashMap;
use autonomi::Client;
use autonomi::register::RegisterAddress;
use bls::PublicKey;
use log::{debug};

#[derive(Clone)]
pub struct Dns {
    dns_register: String,
    client: Client,
    cache: HashMap<String, String>
}

impl Dns {
    pub fn new(client: Client, dns_register: String) -> Self {
        Self {
            dns_register,
            client,
            cache: HashMap::new()
        }
    }

    /*pub async fn resolve_direct(&self, addr: String, use_name: bool) -> color_eyre::Result<String> {
        let secret_key = bls::SecretKey::random(); // todo: get owner's key
        let public_key = secret_key.public_key();
        let (address, printing_name) = self.parse_addr(self.dns_register.as_str(), use_name, public_key)?;

        /*
        EXPERIMENTAL! The design may change as there becomes a standard approach.
        Limitations:
        - Only 1 dns register is looked up against (dns1). Once full, dns2..X should be used.
        - Reading the history of a register edited by the CLI doesn't seem possible right now, so only
          one DNS entry can be set (which is very limiting!).
        - Only 1 site register is looked up against (e.g. traktion1). Once full, traktion2..X should be used
        - Code is a bit hacked together in general, with many failed assumptions breaking silently
         */


        info!("Trying to retrieve DNS register [{}]", printing_name);

        match self.client.register_get(&address).await {
            Ok(register) => {
                debug!("Successfully retrieved DNS register [{}]", printing_name);

                let entries = register.clone();

                // print all entries
                for entry in entries.clone() {
                    let entry_data = entry.to_vec();
                    let data_str = String::from_utf8(entry_data.clone()).unwrap_or_else(|_| format!("{entry_data:?}"));
                    debug!("Entry - data: [{}]", data_str);

                    let Some((name, data)) = data_str.split_once(',') else { continue };
                    if name == addr {
                        debug!("Found DNS entry - name [{}], data: [{}]", name, data);
                        let (dns_address, _) = self.parse_addr(&data, false, public_key.clone())?;
                        match self.client.register_get(&dns_address).await {
                            Ok(site_register) => {
                                let entry = site_register.clone().values();
                                let site_entry_data = entry.last().expect("Failed to retrieve latest site register entry").to_vec();
                                let site_data_str = String::from_utf8(site_entry_data.clone()).unwrap_or_else(|_| format!("{site_entry_data:?}"));
                                info!("Found site register entry [{}]", site_data_str);
                                return Ok(site_data_str);
                            },
                            Err(_) => {
                                continue
                            }
                        }
                    }
                }
                info!("Did not find DNS entry for [{}]", addr);
                Err(Report::msg(addr.to_string()))
            }
            Err(error) => {
                info!(
                    "Did not retrieve DNS register [{}] with error [{}]",
                    printing_name, error
                );
                return Err(error.into());
            }
        }
    }*/

    /*pub async fn resolve(&self, key: String, use_name: bool) -> color_eyre::Result<String> {
       match self.cache.contains_key(&key) {
           true => {
               let value = self.cache.get(&key).unwrap().clone();
               info!("Resolved [{}] to [{}] from DNS cache", key, value);
               Ok(value)
           },
           false => {
               self.resolve_direct(key, use_name).await
           }
       }
    }*/

    /*pub async fn load_cache(&mut self, use_name: bool) {
        let secret_key = bls::SecretKey::random(); // todo: get owner's key
        let public_key = secret_key.public_key();
        let (address, printing_name) = self.parse_addr(self.dns_register.as_str(), use_name, public_key).unwrap();

        info!("Trying to retrieve DNS register [{}]", printing_name);

        match self.client.register_get(&address).await {
            Ok(register) => {
                debug!("Successfully retrieved DNS register [{}]", printing_name);

                let entries = register.clone().values();

                // print all entries
                for entry in entries.clone() {
                    let entry_data = entry.to_vec();
                    let data_str = String::from_utf8(entry_data.clone()).unwrap_or_else(|_| format!("{entry_data:?}"));
                    debug!("Entry - data: [{}]", data_str);

                    let Some((name, data)) = data_str.split_once(',') else { continue };

                    debug!("Found DNS entry - name [{}], data: [{}]", name, data);
                    let (dns_address, _) = self.parse_addr(&data, false, public_key.clone()).unwrap();
                    match self.client.register_get(&dns_address).await {
                        Ok(site_register) => {
                            let entry = site_register.clone().values();
                            let site_entry_data = entry.last().expect("Failed to retrieve latest site register entry").to_vec();
                            let site_data_str = String::from_utf8(site_entry_data.clone()).unwrap_or_else(|_| format!("{site_entry_data:?}"));
                            info!("Adding site register entry [{}]->[{}] to cache", name, site_data_str);
                            self.cache.insert(name.to_string(), site_data_str.clone());
                        },
                        Err(_) => {
                            continue
                        }
                    }
                }
            }
            Err(error) => {
                info!(
                    "Did not retrieve DNS register [{}] with error [{}]",
                    printing_name, error
                );
                return
            }
        }
    }*/

    /*fn parse_addr(
        &self,
        address_str: &str,
        use_name: bool,
        pk: PublicKey,
    ) -> color_eyre::Result<(RegisterAddress, String)> {
        if use_name {
            debug!("Parsing address as name");
            let addr = RegisterAddress::new(pk);
            Ok((addr.clone(), format!("'{address_str}' at {addr}")))
        } else {
            debug!("Parsing address as hex");
            let addr = RegisterAddress::from_hex(address_str).expect("Could not parse hex string");
            Ok((addr, format!("at {address_str}")))
        }
    }*/
}