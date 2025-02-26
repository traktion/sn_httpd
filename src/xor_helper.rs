use actix_http::header::{HeaderMap, IF_NONE_MATCH};
use autonomi::files::PublicArchive;
use log::{debug, info, warn};
use xor_name::XorName;
use crate::caching_client::CachingClient;
use crate::{is_xor, str_to_xor_name};
use crate::archive_helper::{DataState};

#[derive(Clone)]
pub struct XorHelper {
}

impl XorHelper {
    pub fn new() -> XorHelper {
        XorHelper {}
    }
    
    pub fn get_data_state(&self, headers: &HeaderMap, data_addr: XorName) -> DataState {
        if headers.contains_key(IF_NONE_MATCH) {
            let e_tag = headers.get(IF_NONE_MATCH).unwrap().to_str().unwrap();
            let source_e_tag = e_tag.to_string().replace("\"", "");
            let target_e_tag = format!("{:x}", data_addr);
            debug!("is_modified == [{}], source_e_tag = [{}], target_e_tag = [{}], IF_NONE_MATCH present", source_e_tag == target_e_tag, source_e_tag, target_e_tag);
            if source_e_tag != target_e_tag {
                DataState::Modified
            } else {
                DataState::NotModified
            }
        } else {
            debug!("is_modified == [true], IF_NONE_MATCH absent");
            DataState::Modified
        }
    }

    pub async fn resolve_archive_or_file(&self, caching_autonomi_client: &CachingClient, archive_addr: &String, archive_file_name: &String) -> (bool, PublicArchive, bool, XorName) {
        if is_xor(&archive_addr) {
            let archive_addr_xorname = str_to_xor_name(&archive_addr).unwrap();
            match caching_autonomi_client.archive_get_public(archive_addr_xorname).await {
                Ok(public_archive) => {
                    info!("Found archive at [{:x}]", archive_addr_xorname);
                    (true, public_archive, true, archive_addr_xorname)
                }
                Err(_) => {
                    info!("No archive found at [{:x}]. Treating as XOR address", archive_addr_xorname);
                    (true, PublicArchive::new(), false, archive_addr_xorname)
                }
            }
        } else if is_xor(&archive_file_name) {
            let archive_file_name_xorname = str_to_xor_name(&archive_file_name).unwrap();
            info!("Found XOR address [{:x}]", archive_file_name_xorname);
            (true, PublicArchive::new(), false, archive_file_name_xorname)
        } else {
            warn!("Failed to find archive or filename [{:?}]", archive_file_name);
            (false, PublicArchive::new(), false, XorName::default())
        }
    }
}