use actix_http::header;
use actix_web::http::header::{ETag, EntityTag};
use actix_web::{HttpRequest, HttpResponse};
use autonomi::files::PublicArchive;
use log::{info, warn};
use xor_name::XorName;
use crate::archive_helper::{ArchiveAction, ArchiveHelper, DataState};
use crate::caching_client::CachingClient;
use crate::file_client::FileClient;
use crate::xor_helper::XorHelper;

pub struct ArchiveClient {
    caching_autonomi_client: CachingClient,
    file_client: FileClient,
    xor_helper: XorHelper,
}

impl ArchiveClient {
    
    pub fn new(caching_autonomi_client: CachingClient, file_client: FileClient, xor_helper: XorHelper) -> Self {
        ArchiveClient { caching_autonomi_client, file_client, xor_helper }
    }
    
    pub async fn get_data(&self, archive: PublicArchive, xor_addr: XorName, request: HttpRequest, path_parts: Vec<String>) -> HttpResponse {
        let (archive_addr, archive_file_name) = self.xor_helper.assign_path_parts(path_parts.clone());
        info!("archive_addr [{}], archive_file_name [{}]", archive_addr, archive_file_name);
        
        // load app_config from archive and resolve route
        match self.caching_autonomi_client.config_get_public(archive.clone(), xor_addr).await {
            Ok(app_config) => {
                // resolve route
                let archive_relative_path = path_parts[1..].join("/").to_string();
                let (resolved_relative_path_route, has_route_map) = app_config.resolve_route(archive_relative_path.clone(), archive_file_name.clone());

                // resolve file name to chunk address
                let archive_helper = ArchiveHelper::new(archive.clone());
                let archive_info = archive_helper.resolve_archive_info(path_parts, request.clone(), resolved_relative_path_route.clone(), has_route_map);

                if archive_info.state == DataState::NotModified {
                    info!("ETag matches for path [{}] at address [{}]. Client can use cached version", archive_info.path_string, format!("{:x}", archive_info.resolved_xor_addr));
                    HttpResponse::NotModified().into()
                } else if archive_info.action == ArchiveAction::Redirect {
                    info!("Redirect to archive directory [{}]", request.path().to_string() + "/");
                    HttpResponse::MovedPermanently()
                        .insert_header((header::LOCATION, request.path().to_string() + "/"))
                        .finish()
                } else if archive_info.action == ArchiveAction::NotFound {
                    warn!("Path not found {:?}", archive_info.path_string);
                    HttpResponse::NotFound().body(format!("File not found {:?}", archive_info.path_string))
                } else if archive_info.action == ArchiveAction::Listing {
                    info!("List files in archive [{}]", archive_addr);
                    // todo: set header when js file
                    HttpResponse::Ok()
                        .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_addr).to_owned())))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                        .body(archive_helper.list_files(request.headers()))
                } else {
                    self.file_client.download_data_body(archive_relative_path, archive_info.resolved_xor_addr, true).await
                }
            },
            Err(err) => {
                warn!("Failed to load config from map [{:?}]", err);
                HttpResponse::InternalServerError().body(format!("Failed to load config from map [{:?}]", err))
            },
        }
    }
}