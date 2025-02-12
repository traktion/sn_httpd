mod autonomi;
mod config;
mod caching_archive;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware::Logger, HttpRequest};
use actix_web::http::header::{CacheControl, CacheDirective, ContentType, ETag, EntityTag};
use actix_files::Files;
use xor_name::XorName;
use log::{info, debug, warn};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::collections::HashMap;
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
use color_eyre::{Report, Result};
use globset::{Glob};
use awc::Client as AwcClient;
use chrono::{DateTime};
use crate::autonomi::Autonomi;
use crate::caching_archive::CachingClient;
use crate::config::AppConfig;

const XOR_PATH: &str = "xor";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Config {
    route_map: HashMap<String, String>
}
impl Default for Config {
    fn default () -> Config {
        Config{route_map: HashMap::new()}
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // init logging from RUST_LOG env var with info as default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let app_config = AppConfig::read_args().expect("Failed to read CLI arguments");
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
            .route("/{path:.*}", web::get().to(get_safe_data))
            .app_data(Data::new(app_config.clone()))
            .app_data(Data::new(autonomi_client.clone()))
            .app_data(Data::new(AwcClient::default()))
            .app_data(Data::new(evm_wallet.clone()))
    })
        .bind(bind_socket_addr)?
        .run()
        .await
}

async fn get_safe_data(
    request: HttpRequest,
    path: web::Path<String>,
    autonomi_client_data: Data<Client>,
    conn: ConnectionInfo,
    //dns_data: Data<Dns>,
) -> impl Responder {
    let path_parts = get_path_parts(&conn.host(), &path.into_inner());
    let (archive_addr, archive_file_name) = assign_path_parts(path_parts.clone());
    let autonomi_client = autonomi_client_data.get_ref().clone();
    //let dns = dns_data.get_ref();

    info!("archive_addr [{}], archive_file_name [{}]", archive_addr, archive_file_name);

    let caching_autonomi_client = CachingClient::new(autonomi_client.clone());
    let (archive, is_archive, xor_addr) = if archive_addr.to_lowercase() != XOR_PATH {
        let archive_addr_xorname = str_to_xor_name(&archive_addr).unwrap();
        match caching_autonomi_client.archive_get_public(archive_addr_xorname).await {
            Ok(value) => {
                info!("Found archive at [{:x}]", archive_addr_xorname);
                (value, true, archive_addr_xorname)
            },
            Err(_) => {
                info!("No archive found at [{:x}]. Treating as XOR address", archive_addr_xorname);
                (PublicArchive::new(), false, archive_addr_xorname)
            }
        }
    } else if is_xor(&archive_file_name) {
        let archive_file_name_xorname = str_to_xor_name(&archive_file_name).unwrap();
        info!("Found XOR address [{:x}]", archive_file_name_xorname);
        (PublicArchive::new(), false, archive_file_name_xorname)
    } else {
        warn!("Failed to download [{:?}]", archive_file_name);
        return HttpResponse::NotFound().body(format!("Failed to download [{:?}]", archive_file_name));
    };

    if is_archive {
        info!("Retrieving file from archive [{:x}]", xor_addr);

        // load config from subdomain (of .autonomi) or path root
        let config = match get_config(archive.clone(), caching_autonomi_client.clone(), archive_addr.clone()).await {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to load config from map [{:?}]", err);
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to load config from map [{:?}]", err))
            },
        };

        // resolve route
        let (resolved_relative_path_route, has_route_map) = resolve_route(path_parts.clone()[1..].join("/").to_string(), config.clone(), archive_file_name.clone());

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

            if has_route_map {
                get_index(resolved_relative_path_route, archive.clone(), &request)
            } else if !resolved_relative_path_route.is_empty() {
                let data_addr = match resolve_data_addr_from_archive(archive.clone(), path_parts.clone()) {
                    Ok(value) => value,
                    Err(err) => {
                        warn!("{:?}", err);
                        return HttpResponse::NotFound()
                            .body(format!("{:?}", err))
                    }
                };
                info!("Resolved path [{}], path_buf [{}] to xor address [{}]", resolved_relative_path_route, path_buf.display(), format!("{:x}", data_addr));
                (resolved_relative_path_route, data_addr)
            } else {
                info!("List files in archive [{}]", archive_addr);
                if let Some(accept) = request.headers().get("Accept") {
                    if accept.to_str().unwrap().to_string().contains( "json") {
                        return HttpResponse::Ok()
                            .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_addr).to_owned())))
                            .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                            .body(list_archive_files_json(archive.clone()))
                    }
                }
                return HttpResponse::Ok()
                    .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_addr).to_owned())))
                    .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                    .body(list_archive_files(archive.clone()))
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

        download_data_body(path_parts[1..].join("/").to_string(), data_addr, true, autonomi_client).await
    } else {
        // autonomi XOR addr
        info!("Retrieving file from [{:x}]", xor_addr);
        download_data_body(archive_addr, xor_addr, false, autonomi_client).await
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
            if !is_resolved_file_name && is_xor(&format!("{:x}", xor_name)) {
                // cache immutable
                if path_str.ends_with(".js") {
                    HttpResponse::Ok()
                        .insert_header(CacheControl(vec![CacheDirective::MaxAge(31536000u32)]))
                        .insert_header(get_content_type_from_filename(path_str))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                        .body(data)
                } else {
                    HttpResponse::Ok()
                        .insert_header(CacheControl(vec![CacheDirective::MaxAge(31536000u32)]))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                        .body(data)
                }
            } else {
                // etag
                if path_str.ends_with(".js") {
                    HttpResponse::Ok()
                        .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_name).to_owned())))
                        .insert_header(get_content_type_from_filename(path_str))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                        .body(data)
                } else {
                    HttpResponse::Ok()
                        .insert_header(ETag(EntityTag::new_strong(format!("{:x}", xor_name).to_owned())))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
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

async fn get_config(archive: PublicArchive, autonomi_client: CachingClient, archive_addr: String) -> Result<Config> {
    let archive_addr_xorname = str_to_xor_name(&archive_addr)
        .unwrap_or_else(|_| XorName::default());

    let path_str = "app-conf.json";
    let mut path_parts = Vec::<String>::new();
    path_parts.push("ignore".to_string());
    path_parts.push(path_str.to_string());
    match resolve_data_addr_from_archive(archive, path_parts) {
        Ok(data) => {
            info!("Downloading app-config [{}] with addr [{}] from archive [{}]", path_str, format!("{:x}", data), format!("{:x}", archive_addr_xorname));
            match autonomi_client.data_get_public(data).await {
                Ok(data) => {
                    let json = String::from_utf8(data.to_vec()).unwrap_or(String::new());
                    debug!("json [{}]", json);
                    let config: Config = serde_json::from_str(&json.as_str()).unwrap_or(Config::default());

                    Ok(config)
                }
                Err(_e) => {
                    Ok(Config::default())
                }
            }
        },
        Err(_e) => Ok(Config::default())
    }
}

fn resolve_route(relative_path: String, config: Config, archive_file_name: String) -> (String, bool) {
    for (key, value) in config.route_map {
        let glob = Glob::new(key.as_str()).unwrap().compile_matcher();
        debug!("route mapper comparing path [{}] with glob [{}]", relative_path, key);
        if glob.is_match(&relative_path) {
            info!("route mapper resolved path [{}] to [{}] with glob [{}]", relative_path, key, value);
            return (value, true);
        }
    };
    (archive_file_name, false)
}

fn resolve_data_addr_from_archive(archive: PublicArchive, path_parts: Vec<String>) -> Result<DataAddr> {
    archive.iter().for_each(|(path_buf, data_addr, _)| debug!("archive entry: [{}] at [{:x}]", path_buf.display(), data_addr));

    // todo: Replace with contains() once keys are a more useful shape
    let path_parts_string = path_parts[1..].join("/");
    for key in archive.map().keys() {
        if key.to_str().unwrap().to_string().trim_start_matches("./").ends_with(path_parts_string.as_str()) {
            let (data_addr, _) = archive.map().get(key).unwrap();
            return Ok(data_addr.clone())
        }
    }
    Err(Report::msg(format!("Failed to find item [{}] in archive", path_parts_string)))

    /*if archive.map().contains_key(path_buf) {
        let (data_addr, metadata) = archive
            .map()
            .get(path_buf)
            .expect(format!("Failed to retrieve [{}] from archive", path_buf.clone().display()).as_str());
        Ok(data_addr.clone())
    } else {
        Err(Report::msg(format!("Failed to find item [{}] in archive", path_buf.clone().display())))
    }*/
}

fn list_archive_files(archive: PublicArchive) -> String {
    let mut output = "<html><body><ul>".to_string();

    // todo: Replace with contains() once keys are a more useful shape
    for key in archive.map().keys() {
        let filepath = key.to_str().unwrap().to_string().trim_start_matches("./").to_string();
        output.push_str(&format!("<li><a href=\"{}\">{}</a></li>\n", filepath, filepath));
    }
    output.push_str("</ul></body></html>");
    output
}

fn list_archive_files_json(archive: PublicArchive) -> String {
    let mut output = "[\n".to_string();

    let mut i = 1;
    let count = archive.map().keys().len();
    for key in archive.map().keys() {
        let (_, metadata) = archive.map().get(key).unwrap();
        let mtime_datetime = DateTime::from_timestamp_millis(metadata.modified as i64 * 1000).unwrap();
        let mtime_iso = mtime_datetime.format("%+");
        let filepath = key.to_str().unwrap().to_string().trim_start_matches("./").to_string();
        output.push_str("{");
        output.push_str(&format!("\"name\": \"{}\", \"type\": \"file\", \"mtime\": \"{}\", \"size\": \"{}\"", filepath, mtime_iso, metadata.size));
        output.push_str("}");
        if i < count {
            output.push_str(",");
        }
        output.push_str("\n");
        i+=1;
    }
    output.push_str("]");
    output
}

fn get_index(resolved_filename_string: String, archive: PublicArchive, request: &HttpRequest) -> (String, XorName) {
    // hack to return index.html when present in directory root
    for key in archive.map().keys() {
        if key.ends_with(resolved_filename_string.to_string()) {
            let path_string = request.path().to_string() + key.to_str().unwrap();
            let data_addr = archive.map().get(key).unwrap().0;
            return (path_string, data_addr)
        }
    }
    (String::new(), XorName::default())
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