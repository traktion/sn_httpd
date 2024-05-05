use log::{debug, info};
use sn_client::Client;
use sn_client::registers::RegisterAddress;
use sn_client::transfers::bls::PublicKey;
use xor_name::XorName;

#[derive(Clone)]
pub struct Dns {
    dns_register: String,
    client: Client
}

impl Dns {
    pub fn new(client: Client, dns_register: String) -> Self {
        Self {
            dns_register,
            client
        }
    }

    pub async fn resolve(&self, addr: String, use_name: bool) -> color_eyre::Result<String> {
        let (address, printing_name) = self.parse_addr(self.dns_register.as_str(), use_name, self.client.signer_pk())?;

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

        match self.client.get_register(address).await {
            Ok(register) => {
                debug!("Successfully retrieved DNS register [{}]", printing_name);

                let entries = register.clone().read();

                // print all entries
                for entry in entries.clone() {
                    let (hash, entry_data) = entry.clone();
                    let data_str = String::from_utf8(entry_data.clone()).unwrap_or_else(|_| format!("{entry_data:?}"));
                    debug!("Entry - hash [{}], data: [{}]", hash, data_str);

                    let Some((name, data)) = data_str.split_once(',') else { continue };
                    if name == addr {
                        debug!("Found DNS entry - name [{}], data: [{}]", name, data);
                        let (dns_address, _) = self.parse_addr(&data, false, self.client.signer_pk())?;
                        match self.client.get_register(dns_address).await {
                            Ok(site_register) => {
                                let entry = site_register.clone().read();
                                let (_, site_entry_data) = entry.last().expect("Failed to retrieve latest site register entry");
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
                Ok(addr.to_string())
            }
            Err(error) => {
                info!(
                "Did not retrieve DNS register [{}] with error [{}]",
                printing_name, error
            );
                return Err(error.into());
            }
        }
    }

    fn parse_addr(
        &self,
        address_str: &str,
        use_name: bool,
        pk: PublicKey,
    ) -> color_eyre::Result<(RegisterAddress, String)> {
        if use_name {
            debug!("Parsing address as name");
            let user_metadata = XorName::from_content(address_str.as_bytes());
            let addr = RegisterAddress::new(user_metadata, pk);
            Ok((addr, format!("'{address_str}' at {addr}")))
        } else {
            debug!("Parsing address as hex");
            let addr = RegisterAddress::from_hex(address_str).expect("Could not parse hex string");
            Ok((addr, format!("at {address_str}")))
        }
    }
}