mod proxy;
mod autonomi;
mod dns;
mod config;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware::Logger, Error, HttpRequest};
use actix_web::http::header::{CacheControl, CacheDirective, ContentRange, ContentRangeSpec};
use actix_files::Files;
use xor_name::XorName;
use log::{info, error, debug, warn};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::{fs};
use std::collections::HashMap;
use std::fs::{File,create_dir_all};
use std::io::{empty, Write};
use std::path::PathBuf;
use ::autonomi::Client;
use ::autonomi::client::address::str_to_addr;
use ::autonomi::client::archive::{Archive, ArchiveAddr};
use ::autonomi::client::data::{ChunkAddr, DataAddr};
use ::autonomi::EvmNetwork::ArbitrumSepolia;
use actix_web::dev::{ConnectionInfo, PeerAddr};
use actix_web::web::Data;
use bytes::{Bytes};
use async_stream::stream;
use color_eyre::{Report, Result};
use tempfile::{tempdir};
use futures::{StreamExt};
use globset::{Glob};
use awc::Client as AwcClient;
use color_eyre::eyre::Context;
use sn_evm::EvmWallet;
use sn_protocol::storage::{Chunk, ChunkAddress};
use crate::autonomi::Autonomi;
use crate::proxy::Proxy;
use crate::dns::Dns;
use crate::config::AppConfig;

const CLIENT_KEY: &str = "clientkey";
const STREAM_CHUNK_SIZE: usize = 2048 * 1024;
const XOR_PATH: &str = "xor";
const PROXY_ENABLED: bool = false;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Config {
    file_map: HashMap<String, String>,
    route_map: HashMap<String, String>
}
impl Default for Config {
    fn default () -> Config {
        Config{file_map: HashMap::new(), route_map: HashMap::new()}
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // init logging from RUST_LOG env var with info as default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let app_config = AppConfig::read_args().expect("Failed to read CLI arguments");
    let bind_socket_addr = app_config.bind_socket_addr;

    // initialise safe network connection and files api
    let autonomi_client = Autonomi::new(app_config.clone()).init().await;
    let evm_wallet = EvmWallet::new_with_random_wallet(ArbitrumSepolia);
    let mut dns = Dns::new(autonomi_client.clone(), app_config.clone().dns_register);
    dns.load_cache(false).await;

    info!("Starting listener");

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(Files::new("/static", app_config.static_dir.clone()))
            .route("/xor", web::post().to(post_safe_data))
            .route("/{path:.*}", web::get().to(get_safe_data))
            //.service(get_account)
            .app_data(Data::new(app_config.clone()))
            //.app_data(Data::new(files_api.clone()))
            .app_data(Data::new(autonomi_client.clone()))
            .app_data(Data::new(AwcClient::default()))
            .app_data(Data::new(dns.clone()))
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
    dns_data: Data<Dns>,
) -> impl Responder {
    // todo: fix build issue with aarch64 when the proxy is included
    /*if PROXY_ENABLED {
        let proxy = Proxy::new(".autonomi".to_string(), awc_client.get_ref().clone());
        if proxy.is_remote_url(&conn.host()) {
            return match proxy.forward(request, payload, peer_addr).await {
                Ok(value) => value,
                Err(err) => return HttpResponse::InternalServerError()
                    .body(format!("Failed to forward proxy request [{:?}]", err)),
            }
        }
    }*/

    let path_parts = get_path_parts(&conn.host(), &path.into_inner());
    let (archive_name, archive_file_name) = assign_path_parts(path_parts);
    let autonomi_client = autonomi_client_data.get_ref().clone();
    let dns = dns_data.get_ref();

    info!("archive_name [{}], archive_file_name [{}]", archive_name, archive_file_name);

    // resolve chunk address for config using DNS
    let archive_addr = match resolve_chunk_address(dns.clone(), &archive_name).await {
        Ok(value) => value,
        Err(_) => return HttpResponse::NotFound()
            .body(format!("Failed to resolve DNS name [{:?}]", archive_name)),
    };

    let (archive, is_archive, xor_addr) = if archive_addr.to_lowercase() != XOR_PATH {
        let archive_addr_xorname = str_to_xor_name(&archive_addr).unwrap();
        match autonomi_client.archive_get(archive_addr_xorname).await {
            Ok(value) => {
                info!("Found archive at [{:x}]", archive_addr_xorname);
                (value, true, archive_addr_xorname)
            },
            Err(_) => {
                info!("No archive found at [{:x}]. Treating as XOR address", archive_addr_xorname);
                (Archive::new(), false, archive_addr_xorname)
            }
        }
    } else if is_xor(&archive_file_name) {
        let archive_file_name_xorname = str_to_xor_name(&archive_file_name).unwrap();
        info!("Found XOR address [{:x}]", archive_file_name_xorname);
        (Archive::new(), false, archive_file_name_xorname)
    } else {
        warn!("Failed to download [{:?}]", archive_file_name);
        return HttpResponse::NotFound().body(format!("Failed to download [{:?}]", archive_file_name));
    };

    if (is_archive) {
        info!("Retrieving file from archive [{:x}]", xor_addr);

        /*// load config from subdomain (of .autonomi) or path root
        let config = match get_config(archive.clone(), autonomi_client.clone(), archive_addr).await {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to load config from map [{:?}]", err);
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to load config from map [{:?}]", err))
            },
        };

        // resolve route
        let resolved_relative_path_route = match resolve_route(archive_file_name, config.clone()) {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to resolve route [{:?}]", err);
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to resolve route [{:?}]", err))
            },
        };*/

        let resolved_relative_path_route = archive_file_name.clone();

        // resolve file name to chunk address
        let (path_str, data_addr) = if is_xor(&resolved_relative_path_route) {
            let path_str = resolved_relative_path_route.clone();
            let data_addr = str_to_xor_name(&resolved_relative_path_route).unwrap();
            info!("Resolved path is XOR address [{}]", resolved_relative_path_route);
            (path_str, data_addr)
        } else {
            let path_str = "./".to_string() + resolved_relative_path_route.as_str().clone();
            let path_buf = &PathBuf::from(path_str.clone());
            let data_addr = match resolve_data_addr_from_archive(archive.clone(), path_buf) {
                Ok(value) => value,
                Err(err) => {
                    warn!("{:?}", err);
                    return HttpResponse::NotFound()
                        .body(format!("{:?}", err))
                }
            };
            info!("Resolved path [{}], path_buf [{}] to xor address [{}]", resolved_relative_path_route, path_buf.display(), format!("{:x}", data_addr));
            (path_str, data_addr)
        };
        download_data_body(path_str, data_addr, true, autonomi_client).await
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
    let mut chunk_count = 0;
    #[allow(unused_assignments)]
    let mut bytes_read = 0;

    info!("Downloading item [{}] at addr [{}] ", path_str, format!("{:x}", xor_name));
    match autonomi_client.data_get(xor_name).await {
        Ok(data) => {
            chunk_count += 1;
            bytes_read = data.len();
            info!("Read [{}] bytes of item [{}] at addr [{}]", bytes_read, path_str, format!("{:x}", xor_name));
            HttpResponse::Ok()
                .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&format!("{:x}", xor_name), is_resolved_file_name))]))
                .body(data)
        }
        Err(e) => {
            HttpResponse::NotFound().body(format!("Failed to download [{:?}]", e))
        }
    }
}

fn get_range(request: &HttpRequest) -> (u64, u64, u64) {
    if let Some(range) = request.headers().get("Range") {
        let range_str = range.to_str().unwrap();
        debug!("range header [{}]", range_str);
        let range_value = range_str.split_once("=").unwrap().1;
        // todo: cover comma separated too: https://docs.rs/actix-web/latest/actix_web/http/header/enum.Range.html
        if let Some((range_from_str, range_to_str)) = range_value.split_once("-") {
            let range_from = range_from_str.parse::<u64>().unwrap_or_else(|_| 0);
            let range_to = range_to_str.parse::<u64>().unwrap_or_else(|_| u64::MAX);
            let range_length = range_to - range_from;
            (range_from, range_to, range_length)
        } else {
            (0, u64::MAX, u64::MAX)
        }
    } else {
        (0, u64::MAX, u64::MAX)
    }
}

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
}

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

async fn resolve_chunk_address(dns: Dns, chunk_address: &String) -> Result<String> {
    if chunk_address == XOR_PATH || is_xor(chunk_address) {
        debug!("Chunk address is XOR address [{}]", chunk_address);
        Ok(chunk_address.clone())
    } else {
        dns.resolve(chunk_address.clone(), false).await
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

fn calc_cache_max_age(safe_url: &String, is_resolved_file_name: bool) -> u32 {
    // todo: update when NRS (dynamic XOR URL lookup) is available
    if !is_resolved_file_name && is_xor(safe_url) {
        info!("URL is XOR URL (treat as immutable): [{}]", safe_url);
        31536000u32 // cache 'forever'
    } else {
        info!("URL is register URL (treat as mutable): [{}]", safe_url);
        300 // only cache for 5 mins
    }
}

async fn get_config(archive: Archive, autonomi_client: Client, archive_addr: String) -> Result<Config> {
    let archive_addr_xorname = str_to_xor_name(&archive_addr)
        .unwrap_or_else(|_| XorName::default());

    let path = &PathBuf::from("./app-conf.json");
    let data_addr = resolve_data_addr_from_archive(archive, path).unwrap();


    info!("Downloading item [{}] with addr [{}] from archive [{}]", path.display(), format!("{:x}", data_addr), format!("{:x}", archive_addr_xorname));
    match autonomi_client.data_get(data_addr).await {
        Ok(data) => {
            let json = String::from_utf8(data.to_vec()).unwrap_or(String::new());
            let config: Config = serde_json::from_str(&json).expect("Failed to parse json config");

            Ok(config)
        }
        Err(e) => {
            Ok(Config::default())
        }
    }
}

fn resolve_route(relative_path: String, config: Config) -> Result<String> {
    for (key, value) in config.route_map {
        let glob = Glob::new(key.as_str())?.compile_matcher();
        debug!("route mapper comparing path [{}] with glob [{}]", relative_path, key);
        if glob.is_match(&relative_path) {
            info!("route mapper resolved path [{}] to [{}] with glob [{}]", relative_path, key, value);
            return Ok(value)
        }
    };
    Ok(relative_path)
}

fn resolve_file_name(config: Config, relative_path: String) -> Result<(bool, String)> {
    return if is_xor(&relative_path) {
        Ok((false, relative_path))
    } else if config.file_map.contains_key(&relative_path) {
        let entry = config.file_map.get(&relative_path).expect("Failed to retrieve path from map").to_string();
        info!("file mapper resolved path [{}] to chunk_address [{}]", relative_path, entry);
        Ok((true, entry))
    } else {
        Err(Report::msg(format!("relative_path is neither XOR nor in the data map [{}]", relative_path)))
    }
}

fn resolve_data_addr_from_archive(archive: Archive, path_buf: &PathBuf) -> Result<DataAddr> {
    archive.iter().for_each(|(path_buf, data_addr, _)| debug!("archive entry: [{}] at [{:x}]", path_buf.display(), data_addr));

    if archive.map().contains_key(path_buf) {
        let (data_addr, metadata) = archive
            .map()
            .get(path_buf)
            .expect(format!("Failed to retrieve [{}] from archive", path_buf.clone().display()).as_str());
        Ok(data_addr.clone())
    } else {
        Err(Report::msg(format!("Failed to find item [{}] in archive", path_buf.clone().display())))
    }
}