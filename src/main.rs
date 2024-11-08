mod proxy;
mod autonomi;
mod dns;
mod config;

use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware::Logger, Error, HttpRequest};
use actix_web::http::header::{CacheControl, CacheDirective, ContentRange, ContentRangeSpec};
use actix_files::Files;
use xor_name::XorName;
use log::{info, error, debug};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::{fs};
use std::collections::HashMap;
use std::fs::{File,create_dir_all};
use std::io::{Write};
use ::autonomi::Client;
use ::autonomi::client::address::str_to_addr;
use ::autonomi::client::data::ChunkAddr;
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
const SAFE_PATH: &str = "safe";
const PROXY_ENABLED: bool = false;

/*#[derive(Clone, Default)]
struct Accounts {
    accounts: HashMap<String, Site>
}*/

/*#[derive(Clone)]
struct Site {
    configurl: String,
    keyxorurl: String,
    //keypair: Keypair,
    credit: i64,
    usage: i64
}*/

/*#[derive(Clone)]
struct Urls {
    urls: HashMap<String, Site>
}*/

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
    let dns = Dns::new(autonomi_client.clone(), app_config.clone().dns_register);

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(Files::new("/static", app_config.static_dir.clone()))
            .route("/safe", web::post().to(post_safe_data))
            .route("/{path:.*}", web::get().to(get_safe_data_stream))
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

async fn get_safe_data_stream(
    request: HttpRequest,
    path: web::Path<String>,
    autonomi_client_data: Data<Client>,
    conn: ConnectionInfo,
    payload: web::Payload,
    peer_addr: Option<PeerAddr>,
    awc_client: web::Data<AwcClient>,
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

    let (config_addr, relative_path) = get_config_and_relative_path(&conn.host(), &path.into_inner());
    let autonomy_client = autonomi_client_data.get_ref().clone();
    let dns = dns_data.get_ref();

    info!("config_addr [{}], relative_path [{}]", config_addr, relative_path);

    // resolve chunk address for config using DNS
    let resolved_config_addr = match resolve_chunk_address(dns.clone(), &config_addr).await {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError()
            .body(format!("Failed to resolve DNS name [{:?}]", config_addr)),
    };

    // if the app-config.json is being looked up, copy the resolved chunk address of the config
    let resolved_relative_path = if relative_path == "app-config.json" {
        resolved_config_addr.clone()
    } else {
        relative_path.clone()
    };

    // load config from subdomain (of .autonomi) or path root
    let config = match get_config(autonomy_client.clone(), config_addr, resolved_config_addr).await {
        Ok(value) => value,
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("Failed to load config from map [{:?}]", err)),
    };

    // resolve route
    let resolved_relative_path = match resolve_route(resolved_relative_path, config.clone()) {
        Ok(value) => value,
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("Failed to resolve route [{:?}]", err)),
    };

    // resolve file name to chunk address
    let (is_resolved_file_name, chunk_address) = match resolve_file_name(config, resolved_relative_path) {
        Ok(value) => value,
        Err(err) => return HttpResponse::NotFound()
            .body(format!("Failed to resolve path [{:?}]", err)),
    };

    let (range_from, range_to, _) = get_range(&request);

    download_data_body(chunk_address, is_resolved_file_name, autonomy_client, range_from, range_to).await
}

async fn download_data_body(
    chunk_address: String,
    is_resolved_file_name: bool,
    autonomi_client: Client,
    range_from: u64,
    range_to: u64
) -> HttpResponse {
    // convert chunk address to xor_name
    let xor_name = str_to_addr(&chunk_address).unwrap();

    let mut chunk_count = 0;
    #[allow(unused_assignments)]
    let mut bytes_read = 0;

    // todo: get first chunk synchronously + if bytes < STREAM_CHUNK_SIZE, return non-chunked response

    // todo: understand archives and how to download chunks separately
    let archive = autonomi_client
        .archive_get(xor_name)
        .await
        .unwrap();

    let (_, addr, _) = archive.iter().next().unwrap(); // todo: get all elements in archive?
    info!("Downloading item [{}] from archive [{}]", addr, xor_name);
    match autonomi_client.data_get(*addr).await {
        Ok(data) => {
            chunk_count += 1;
            bytes_read = data.len();
            info!("Read [{}] bytes of item [{}] from archive [{}]", bytes_read, addr, xor_name);
            HttpResponse::Ok()
                .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&chunk_address, is_resolved_file_name))]))
                .body(data)
        }
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Failed to download [{:?}]", e))
        }
    }
}

fn download_data_stream(
    chunk_address: String,
    is_resolved_file_name: bool,
    autonomi_client: Client,
    range_from: u64,
    range_to: u64
) -> impl Responder {
    // todo: When the XOR address is not found, return a 404 instead of falling back on ERR_INCOMPLETE_CHUNKED_ENCODING

    // convert chunk address to xor_name
    let xor_name = str_to_addr(&chunk_address).unwrap();

    let mut chunk_count = 0;
    let mut position_start: usize = u64::try_into(range_from).unwrap();
    let position_end: usize = u64::try_into(range_to).unwrap();
    #[allow(unused_assignments)]
    let mut bytes_read = 0;

    // todo: get first chunk synchronously + if bytes < STREAM_CHUNK_SIZE, return non-chunked response
    let data_stream = stream! {
        //loop {
            /*let chunk_size = if position_end - position_start > STREAM_CHUNK_SIZE {
                STREAM_CHUNK_SIZE
            } else {
                position_end - position_start
            };*/

            // todo: understand archives and how to download chunks separately
            let archive = autonomi_client
                .archive_get(xor_name)
                .await
                .unwrap();

            let (_, addr, _) = archive.iter().next().unwrap(); // todo: get all elements in archive?
            info!("Downloading item [{}] from archive [{}]", addr, xor_name);
            //match files_download.download_from(ChunkAddress::new(xor_name), position_start, chunk_size).await {
            match autonomi_client.data_get(*addr).await {
                Ok(data) => {
                    chunk_count += 1;
                    bytes_read = data.len();
                    info!("Read [{}] bytes from file position [{}] of item [{}] from archive [{}]", bytes_read, position_start, addr, xor_name);
                    yield Ok(data.clone()); // Yielding the chunk here

                    // todo: re-enable multi-chunk streams later
                    /*if bytes_read < STREAM_CHUNK_SIZE {
                        // If the last data chunk returned is smaller than the stream chunk size
                        // it indicates it is the last chunk in the sequence
                        info!("Last chunk [{}] read for XOR address [{}] - breaking", chunk_count, xor_name);
                        break;
                    }
                    position_start += chunk_size;*/
                }
                Err(e) => {
                    error!("Error reading file: {}", e);
                    yield Err(e);
                    //break; // todo: re-enable multi-chunk streams later
                }
            }
        //}
    };

    // todo: When there is only 1 known chunk, we could use body (with 'content-length: x') instead of
    //       streaming (with 'transfer-encoding: chunked') to improve performance.
    /*if request.headers().contains_key("Range") {
        let real_range_size: u64 = if position_end - position_start > STREAM_CHUNK_SIZE {
            STREAM_CHUNK_SIZE.try_into().unwrap()
        } else {
            (position_end - position_start).try_into().unwrap()
        };

        HttpResponse::PartialContent()
            .insert_header(ContentRange(ContentRangeSpec::Bytes {range: Some((range_from, range_from + real_range_size)), instance_length: None}))
            .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&chunk_address, is_resolved_file_name))]))
            .streaming(data_stream)
    } else {*/
    HttpResponse::Ok()
        .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&chunk_address, is_resolved_file_name))]))
        .streaming(data_stream)
    //}
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

// todo: understand what I was trying to do here 3 years ago... :)
/*#[get("/account/{xor}")]
async fn get_account(path: web::Path<String>, app_config: web::Data<AppConfig>, accounts: web::Data<Mutex<Accounts>>, urls: web::Data<Mutex<Urls>>) -> impl Responder {
    let xor_str = path.into_inner();
    let xor_name = str_to_xor_name(&xor_str);
    let safe_url = format!("safe://{}", xor_str);

    let mut client = safe_connect().await;
    if let err = Err(client).is_err() {
        error!("Failed to connect to Safe Network [{:?}]", err);
        return HttpResponse::InternalServerError()
            .body(format!("Failed to connect to Safe Network [{:?}]", err))
    };

    let files_api = match FilesApi::build(client.clone(), Path::new("./").to_path_buf()) {
        Ok(data) => {
            data
        }
        Err(err) => {
            error!("Failed to instantiate FilesApi for Safe Network [{:?}]", err);
            return HttpResponse::InternalServerError()
                .body(format!("Failed to instantiate FilesApi for Safe Network [{:?}]", err))
        }
    };

    // todo: check defaults are good
    let mut files_download = FilesDownload::new(files_api.clone());

    // todo: get events
    //let mut download_events_rx = files_download.get_events();

    // todo: stream chunks as they come in to improve performance
    return match files_download.download_from(ChunkAddress::new(xor_name), 0, usize::MAX).await {
        Ok(data) => {
            info!("Successfully retrieved data at [{}]!", safe_url);

            for (key, value) in accounts.lock().await.accounts.iter() {
                info!("Accounts - {}: {}", key, value.keyxorurl);
            }

            for (key, value) in urls.lock().await.urls.iter() {
                info!("URLs - {}: {}", key, value.keyxorurl);
            }

            if !accounts.lock().await.accounts.contains_key(&safe_url) {
                info!("Site does not exist. Creating [{}]", safe_url);
                let (key_xorurl, key_pair): (String, Keypair) = match safe.keys_create_and_preload("0.000000001").await {
                    Ok(data) => data,
                    Err(err) => {
                        error!("Failed to create key [{:?}]", err);
                        return HttpResponse::InternalServerError()
                            .body(format!("Failed to create key [{:?}]", err))
                    }
                };
                let site = Site {
                    configurl: safe_url.clone(),
                    keyxorurl: key_xorurl.clone(),
                    keypair: key_pair,
                    credit: 0,
                    usage: 0
                };
                // associate site with requested safe_url for config
                accounts.lock().await.accounts.insert(safe_url.clone(), site.clone());
                urls.lock().await.urls.insert(safe_url.clone(), site.clone());
                info!("Added site [{}]", safe_url);

                let json = String::from_utf8(data).unwrap_or(String::new());
                let c: Config = serde_json::from_str(&json).unwrap(); // todo: error handling
                for url in c.urls.iter() {
                    // associate urls in config with site
                    urls.lock().await.urls.insert(url.clone(), site.clone());
                    info!("Added URL [{}] to site [{:?}]", url, site.configurl);
                }

                for (key, value) in accounts.lock().await.accounts.iter() {
                    info!("Accounts - {}: {}", key, value.keyxorurl);
                }

                for (key, value) in urls.lock().await.urls.iter() {
                    info!("URLs - {}: {}", key, value.keyxorurl);
                }

                HttpResponse::Ok()
                    .body(format!("Account created. Send coins here to fund account: [{}]", key_xorurl))
            } else {
                if let Some(site) = accounts.lock().await.accounts.get(&safe_url) {
                    HttpResponse::Ok()
                        .body(format!("Account exists. Send coins here to fund account: [{}]", site.keyxorurl))
                } else {
                    HttpResponse::InternalServerError()
                        .body(format!("Failed to retrieve site details for URL [{}]", safe_url))
                }
            }
        }
        Err(err) => {
            warn!("Failed to retrieve data at [{}]: {:?}", safe_url, err);
            HttpResponse::NotFound()
                .body(format!("Failed to retrieve data at [{}]: {:?}", safe_url, err))
        },
    }
}*/

fn get_config_and_relative_path(hostname: &str, path: &str) -> (String, String) {
    // assert: subdomain.autonomi as acceptable format
    return if hostname.ends_with(".autonomi") {
        let subdomain = hostname.split_once(".").unwrap().0.to_string();
        (subdomain, path.to_string())
    } else {
        if path.contains("/") {
            let (part1, part2) = path.split_once("/").unwrap();
            (part1.to_string(), part2.to_string())
        } else {
            (path.to_string(), path.to_string())
        }
    }
}

async fn resolve_chunk_address(dns: Dns, chunk_address: &String) -> Result<String> {
    return if chunk_address != SAFE_PATH && !is_xor(chunk_address) {
        dns.resolve(chunk_address.clone(), false).await
    } else {
        Ok(chunk_address.clone())
    }
}

fn is_xor_len(chunk_address: &String) -> bool {
    return chunk_address.len() == 64;
}

fn is_xor(chunk_address: &String) -> bool {
    return is_xor_len(chunk_address) && str_to_xor_name(chunk_address).is_ok();
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
    return if !is_resolved_file_name && is_xor(safe_url) {
        info!("URL is XOR URL (treat as immutable): [{}]", safe_url);
        31536000u32 // cache 'forever'
    } else {
        info!("URL is register URL (treat as mutable): [{}]", safe_url);
        30 // only cache for 30s
    }
}

//async fn get_config(files_api: FilesApi, config_addr: String, resolved_config_addr: String) -> Result<Config> {
async fn get_config(autonomi_client: Client, config_addr: String, resolved_config_addr: String) -> Result<Config> {
    if config_addr != SAFE_PATH && config_addr != "" {
        //let mut files_download = FilesDownload::new(autonomy_client.clone());

        let config_xor_name = str_to_xor_name(&resolved_config_addr)
            .unwrap_or_else(|_| XorName::default());
        //let chunk_addr = ChunkAddress::new(config_xor_name);
        //let data = files_download.download_file(chunk_addr, None).await?;
        let chunk_addr = ChunkAddr::from_content(config_xor_name.as_ref());
        let data = autonomi_client.chunk_get(chunk_addr).await?;

        //let json = String::from_utf8(data.to_vec()).unwrap_or(String::new());
        let json = String::from_utf8(data.value().to_vec()).unwrap_or(String::new());
        let config: Config = serde_json::from_str(&json).expect("Failed to parse json config");

        Ok(config)
    } else {
        Ok(Config::default())
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
