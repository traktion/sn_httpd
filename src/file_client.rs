use actix_http::header;
use actix_web::{HttpRequest, HttpResponse};
use actix_web::dev::ConnectionInfo;
use actix_web::http::header::{CacheControl, CacheDirective, ContentType, ETag, EntityTag};
use autonomi::Client;
use autonomi::data::DataAddr;
use log::info;
use xor_name::XorName;
use crate::archive_helper::DataState;
use crate::xor_helper::XorHelper;

pub struct FileClient {
    autonomi_client: Client,
    xor_helper: XorHelper,
    conn: ConnectionInfo
}

impl FileClient {
    pub fn new(autonomi_client: Client, xor_helper: XorHelper, conn: ConnectionInfo) -> Self {
        FileClient { autonomi_client, xor_helper, conn }
    }

    pub async fn get_data(&self, path_parts: Vec<String>, request: HttpRequest, xor_addr: XorName, is_found: bool) -> HttpResponse {
        let (archive_addr, _) = self.xor_helper.assign_path_parts(path_parts.clone());
        info!("archive_addr [{}]", archive_addr);
        
        if self.xor_helper.get_data_state(request.headers(), xor_addr) == DataState::NotModified {
            info!("ETag matches for path [{}] at address [{}]. Client can use cached version", archive_addr, format!("{:x}", xor_addr));
            HttpResponse::NotModified().into()
        } else if !is_found {
            HttpResponse::NotFound().body(format!("File not found {:?}", self.conn.host()))
        } else {
            self.download_data_body(archive_addr, xor_addr, false).await
        }
    }

    pub async fn download_data_body(
        &self,
        path_str: String,
        xor_name: DataAddr,
        is_resolved_file_name: bool
    ) -> HttpResponse {
        info!("Downloading item [{}] at addr [{}] ", path_str, format!("{:x}", xor_name));
        match self.autonomi_client.data_get_public(xor_name.as_ref()).await {
            Ok(data) => {
                info!("Read [{}] bytes of item [{}] at addr [{}]", data.len(), path_str, format!("{:x}", xor_name));
                let cache_control_header = self.build_cache_control_header(&xor_name, is_resolved_file_name);
                let etag_header = ETag(EntityTag::new_strong(format!("{:x}", xor_name).to_owned()));
                let cors_allow_all = (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

                if path_str.ends_with(".js") {
                    HttpResponse::Ok()
                        .insert_header(cache_control_header)
                        .insert_header(etag_header)
                        .insert_header(cors_allow_all)
                        .insert_header(self.get_content_type_from_filename(path_str)) // todo: why necessary?
                        .body(data)
                } else {
                    HttpResponse::Ok()
                        .insert_header(cache_control_header)
                        .insert_header(etag_header)
                        .insert_header(cors_allow_all)
                        .body(data)
                }
            }
            Err(e) => {
                HttpResponse::InternalServerError().body(format!("Failed to download [{:?}]", e))
            }
        }
    }

    fn build_cache_control_header(&self, xor_name: &DataAddr, is_resolved_file_name: bool) -> CacheControl {
        if !is_resolved_file_name && self.xor_helper.is_xor(&format!("{:x}", xor_name)) {
            CacheControl(vec![CacheDirective::MaxAge(31536000u32)]) // immutable
        } else {
            CacheControl(vec![CacheDirective::MaxAge(0u32)]) // mutable
        }
    }

    fn get_content_type_from_filename(&self, filename: String) -> ContentType {
        if filename.ends_with(".js") {
            ContentType(mime::APPLICATION_JAVASCRIPT)
        } else if filename.ends_with(".html") {
            ContentType(mime::TEXT_HTML)
        } else if filename.ends_with(".css") {
            ContentType(mime::TEXT_CSS)
        } else {
            ContentType(mime::TEXT_PLAIN) // todo: use actix function to derive default
        }
    }
}