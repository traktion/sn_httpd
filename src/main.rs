mod autonomi;
mod anttp_config;
mod caching_client;
mod app_config;
mod archive_helper;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware::Logger, HttpRequest};
use actix_web::http::header::{CacheControl, CacheDirective, ContentType, ETag, EntityTag};
use actix_files::Files;
use xor_name::XorName;
use log::{info, warn};
use std::convert::TryInto;
use std::path::PathBuf;
use ::autonomi::Client;
use ::autonomi::client::data::{DataAddr};
use ::autonomi::client::files::archive_public::PublicArchive;
use ::autonomi::Network::ArbitrumSepolia;
use actix_http::{header};
use actix_http::header::IF_NONE_MATCH;
use actix_web::dev::{ConnectionInfo};
use actix_web::web::Data;
use ant_evm::EvmWallet;
use color_eyre::{Result};
use awc::Client as AwcClient;
use crate::autonomi::Autonomi;
use crate::caching_client::CachingClient;
use crate::anttp_config::AntTpConfig;
use crate::archive_helper::ArchiveHelper;

const DEFAULT_LOGGING: &'static str = "info,anttp=info,ant_api=warn,ant_client=warn,ant_networking=off,ant_bootstrap=error";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // init logging from RUST_LOG env var with info as default
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or(DEFAULT_LOGGING))
        .init();

    let app_config = AntTpConfig::read_args().expect("Failed to read CLI arguments");
    let bind_socket_addr = app_config.bind_socket_addr;

    // initialise safe network connection and files api
    let autonomi_client = Autonomi::new().init().await;
    let evm_wallet = EvmWallet::new_with_random_wallet(ArbitrumSepolia);

    info!("Starting listener");

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(Files::new("/static", app_config.static_dir.clone()))
            //.route("/", web::post().to(post_safe_data))
            .route("/{path:.*}", web::get().to(get_public_data))
            .app_data(Data::new(app_config.clone()))
            .app_data(Data::new(autonomi_client.clone()))
            .app_data(Data::new(AwcClient::default()))
            .app_data(Data::new(evm_wallet.clone()))
    })
        .bind(bind_socket_addr)?
        .run()
        .await
}

async fn get_public_data(
    request: HttpRequest,
    path: web::Path<String>,
    autonomi_client_data: Data<Client>,
    conn: ConnectionInfo
) -> impl Responder {
    let path_parts = get_path_parts(&conn.host(), &path.into_inner());
    let (archive_addr, archive_file_name) = assign_path_parts(path_parts.clone());
    let autonomi_client = autonomi_client_data.get_ref().clone();

    info!("archive_addr [{}], archive_file_name [{}]", archive_addr, archive_file_name);

    let caching_autonomi_client = CachingClient::new(autonomi_client.clone());
    let (is_found, archive, is_archive, xor_addr) = resolve_archive_or_file(&caching_autonomi_client, &archive_addr, &archive_file_name).await;

    if !is_found {
        HttpResponse::NotFound().body(format!("Failed to download [{:?}], [{:?}]", archive_addr, archive_file_name))
    } else if is_archive {
        info!("Retrieving file from archive [{:x}]", xor_addr);

        // load app_config from archive and resolve route
        let archive_relative_path = path_parts[1..].join("/").to_string();
        let (resolved_relative_path_route, has_route_map) = match caching_autonomi_client.config_get_public(archive.clone(), xor_addr).await {
            Ok(app_config) => {
                // resolve route
                app_config.resolve_route(archive_relative_path.clone(), archive_file_name.clone())
            },
            Err(err) => {
                warn!("Failed to load config from map [{:?}]", err);
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to load config from map [{:?}]", err))
            },
        };
        
        // resolve file name to chunk address
        let (path_string, data_addr) = if is_xor(&resolved_relative_path_route) {
            let path_string = resolved_relative_path_route.clone();
            let data_addr = str_to_xor_name(&resolved_relative_path_route).unwrap();
            info!("Resolved path is XOR address [{}]", resolved_relative_path_route);
            (path_string, data_addr)
        } else {
            let path_buf = &PathBuf::from(resolved_relative_path_route.clone());
            if resolved_relative_path_route.is_empty() && request.path().to_string().chars().last() != Some('/') {
                info!("Redirect to archive directory [{}]", request.path().to_string() + "/");
                return HttpResponse::MovedPermanently()
                    .insert_header((header::LOCATION, request.path().to_string() + "/"))
                    .finish();
            }

            let archive_helper = ArchiveHelper::new(archive.clone());
            if has_route_map {
                archive_helper.get_index(request.path().to_string(), resolved_relative_path_route)
            } else if !resolved_relative_path_route.is_empty() {
                match archive_helper.resolve_data_addr(path_parts.clone()) {
                    Ok(data_addr) => {
                        info!("Resolved path [{}], path_buf [{}] to xor address [{}]", resolved_relative_path_route, path_buf.display(), format!("{:x}", data_addr));
                        (resolved_relative_path_route, data_addr)
                    }
                    Err(err) => {
                        warn!("{:?}", err);
                        return HttpResponse::NotFound()
                            .body(format!("{:?}", err))
                    }
                }
            } else {
                info!("List files in archive [{}]", archive_addr);
                // todo: set header when js file
                return HttpResponse::Ok()
                    .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_addr).to_owned())))
                    .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                    .body(archive_helper.list_files(request.headers()))
            }
        };

        if request.headers().contains_key(IF_NONE_MATCH) {
            let e_tag = request.headers().get(IF_NONE_MATCH).unwrap().to_str().unwrap();
            let source_e_tag = e_tag.to_string().replace("\"", "");
            let target_e_tag = format!("{:x}", data_addr);
            if source_e_tag == target_e_tag {
                info!("ETag matches for path [{}] at address [{}]. Client can use cached version", path_string, format!("{:x}", data_addr));
                return HttpResponse::NotModified().into()
            }
        }

        download_data_body(archive_relative_path, data_addr, true, autonomi_client).await
    } else {
        info!("Retrieving file from XOR [{:x}]", xor_addr);
        download_data_body(archive_addr, xor_addr, false, autonomi_client).await
    }
}

async fn resolve_archive_or_file(caching_autonomi_client: &CachingClient, archive_addr: &String, archive_file_name: &String) -> (bool, PublicArchive, bool, XorName) {
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

async fn download_data_body(
    path_str: String,
    xor_name: DataAddr,
    is_resolved_file_name: bool,
    autonomi_client: Client
) -> HttpResponse {
    #[allow(unused_assignments)]
    let mut bytes_read = 0;

    info!("Downloading item [{}] at addr [{}] ", path_str, format!("{:x}", xor_name));
    match autonomi_client.data_get_public(xor_name.as_ref()).await {
        Ok(data) => {
            bytes_read = data.len();
            info!("Read [{}] bytes of item [{}] at addr [{}]", bytes_read, path_str, format!("{:x}", xor_name));
            let cors_allow_all = (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            if !is_resolved_file_name && is_xor(&format!("{:x}", xor_name)) {
                // cache immutable
                let immutable_cache_control_header = CacheControl(vec![CacheDirective::MaxAge(31536000u32)]);
                if path_str.ends_with(".js") {
                    HttpResponse::Ok()
                        .insert_header(immutable_cache_control_header)
                        .insert_header(get_content_type_from_filename(path_str))
                        .insert_header(cors_allow_all)
                        .body(data)
                } else {
                    HttpResponse::Ok()
                        .insert_header(immutable_cache_control_header)
                        .insert_header(cors_allow_all)
                        .body(data)
                }
            } else {
                // etag
                let etag_header = ETag(EntityTag::new_strong(format!("{:x}", xor_name).to_owned()));
                if path_str.ends_with(".js") {
                    HttpResponse::Ok()
                        .insert_header(etag_header)
                        .insert_header(get_content_type_from_filename(path_str))
                        .insert_header(cors_allow_all)
                        .body(data)
                } else {
                    HttpResponse::Ok()
                        .insert_header(etag_header)
                        .insert_header(cors_allow_all)
                        .body(data)
                }
            }
        }
        Err(e) => {
            HttpResponse::NotFound().body(format!("Failed to download [{:?}]", e))
        }
    }
}

/*
// experimental file uploads
async fn post_safe_data(mut payload: web::Payload, autonomi_client_data: Data<Client>, evm_wallet_data: Data<EvmWallet>) -> Result<HttpResponse, Error> {
    info!("Post file");
    let autonomi_client = autonomi_client_data.get_ref().clone();
    let evm_wallet = evm_wallet_data.get_ref().clone();

    info!("Creating temp file");
    let temp_dir = tempdir()?;
    let file_path = temp_dir.path().join("tempfile");
    let mut file = File::create(&file_path)?;

    info!("Writing temp file");
    // todo: can we write directly to safe net from memory?
    // Field in turn is stream of *Bytes* object
    while let Some(chunk) = payload.next().await {
        let data = chunk.unwrap();
        // filesystem operations are blocking, we have to use threadpool
        file = web::block(move || file.write_all(&data).map(|_| file))
            .await
            .unwrap()?;
    }

    info!("Creating chunk path");
    let chunk_path = temp_dir.path().join("chunk_path");
    create_dir_all(chunk_path.clone())?;

    info!("Uploading chunks");
    let data_addr = autonomi_client.data_put(Bytes::from(fs::read(chunk_path)?), evm_wallet_data.get_ref()).await.unwrap();

    info!("Successfully uploaded data at [{}]", data_addr);
    Ok(HttpResponse::Ok()
        .body(data_addr.to_string()))
}*/

fn get_path_parts(hostname: &str, path: &str) -> Vec<String> {
    // assert: subdomain.autonomi as acceptable format
    if hostname.ends_with(".autonomi") {
        let mut subdomain_parts = hostname.split(".")
            .map(str::to_string)
            .collect::<Vec<String>>();
        subdomain_parts.pop(); // discard 'autonomi' suffix
        let path_parts = path.split("/")
            .map(str::to_string)
            .collect::<Vec<String>>();
        subdomain_parts.append(&mut path_parts.clone());
        subdomain_parts
    } else if is_xor(&hostname.to_string()) {
        let mut subdomain_parts = Vec::new();
        subdomain_parts.push(hostname.to_string());
        let path_parts = path.split("/")
            .map(str::to_string)
            .collect::<Vec<String>>();
        subdomain_parts.append(&mut path_parts.clone());
        subdomain_parts
    } else {
        let path_parts = path.split("/")
            .map(str::to_string)
            .collect::<Vec<String>>();
        path_parts.clone()
    }
}

fn assign_path_parts(path_parts: Vec<String>) -> (String, String) {
    if path_parts.len() > 1 {
        (path_parts[0].to_string(), path_parts[1].to_string())
    } else if path_parts.len() > 0 {
        (path_parts[0].to_string(), "".to_string())
    } else {
        ("".to_string(), "".to_string())
    }
}

fn is_xor_len(chunk_address: &String) -> bool {
    chunk_address.len() == 64
}

fn is_xor(chunk_address: &String) -> bool {
    is_xor_len(chunk_address) && str_to_xor_name(chunk_address).is_ok()
}

fn str_to_xor_name(str: &String) -> Result<XorName> {
    let bytes = hex::decode(str)?;
    let xor_name_bytes: [u8; 32] = bytes
        .try_into()
        .expect("Failed to parse XorName from hex string");
    Ok(XorName(xor_name_bytes))
}

fn get_content_type_from_filename(filename: String) -> ContentType {
    if filename.ends_with(".js") {
        ContentType(mime::APPLICATION_JAVASCRIPT)
    } else if filename.ends_with(".html") {
        ContentType(mime::TEXT_HTML)
    } else if filename.ends_with(".css") {
        ContentType(mime::TEXT_CSS)
    } else {
        ContentType(mime::TEXT_PLAIN)
    }
}