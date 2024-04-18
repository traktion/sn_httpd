use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, middleware::Logger, Error, post};
use actix_web::http::header::{CacheControl, CacheDirective};
use actix_files::Files;
use anyhow::{anyhow};
use xor_name::XorName;
use log::{info, error, debug};
use std::net::SocketAddr;
use std::env::args;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::{fs};
use std::collections::HashMap;
use std::fs::{File,create_dir_all};
use std::io::{Write};
use std::path::PathBuf;
use std::path::Path;
use actix_web::web::Data;
use bytes::{Bytes};
use async_stream::stream;
use sn_client::transfers::bls::SecretKey;
use sn_client::transfers::bls_secret_from_hex;
use sn_client::{Client, ClientEventsBroadcaster, FilesApi, FilesDownload};
use sn_peers_acquisition::{get_peers_from_args, PeersArgs};
use color_eyre::{Result};
use multiaddr::Multiaddr;
use sn_client::protocol::storage::{Chunk, ChunkAddress};
use tempfile::{tempdir};
use futures::{StreamExt};
use globset::{Glob};
use sn_client::registers::RegisterAddress;
use sn_transfers::bls::PublicKey;

const CLIENT_KEY: &str = "clientkey";
const DNS1: &str = "6d70bf50aec7ebb0f1b9ff5a98e2be2f9deb2017515a28d6aea0c6f80a9f44dd8f1cddbfbd2d975b19912dfd01e3c02077470177455a47814002d5a0f30e886720cc892a3b31f69bf4dae3d2d455fe21";
const STREAM_CHUNK_SIZE: usize = 2048 * 1024;
const SAFE_PATH: &str = "safe";

#[derive(Clone)]
struct AppConfig {
    bind_socket_addr: SocketAddr,
    static_dir: String,
    network_peer_addr: Multiaddr,
}

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

    let app_config = read_args().expect("Failed to read CLI arguments");
    let bind_socket_addr = app_config.bind_socket_addr;

    // initialise safe network connection and files api
    let client = safe_connect(&app_config.network_peer_addr).await.expect("Failed to connect to Safe Network");
    let data_dir_path = get_client_data_dir_path().expect("Failed to get client data dir path");
    let files_api = FilesApi::build(client.clone(), data_dir_path).expect("Failed to instantiate FilesApi");

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(Files::new("/static", app_config.static_dir.clone()))
            .route("/safe", web::post().to(post_safe_data))
            .route("/{path1}", web::get().to(get_safe_data_stream))
            .route("/{path1}/{tail:.*}", web::get().to(get_safe_data_stream))
            //.service(get_account)
            .app_data(Data::new(app_config.clone()))
            .app_data(Data::new(files_api.clone()))
            .app_data(Data::new(client.clone()))
    })
        .bind(bind_socket_addr)?
        .run()
        .await
}

fn read_args() -> Result<AppConfig> {
    // Skip executable name form args
    let mut args_received = args();
    args_received.next();

    // Read the network contact socket address from first arg passed
    let bind_addr = args_received
        .next().expect("No bind address provided");
    let bind_socket_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|err| anyhow!("Invalid bind socket address: {}", err)).unwrap();
    info!("Bind address [{}]", bind_socket_addr);

    // Read the network contact socket address from second arg passed
    let static_dir = args_received
        .next().expect("No static dir provided");
    info!("Static file directory: [{}]", static_dir);

    // Read the network contact peer multiaddr from third arg passed
    let network_contact = args_received
        .next().expect("No Safe network peer address provided");
    let network_peer_addr: Multiaddr = network_contact
        .parse::<Multiaddr>()
        .map_err(|err| anyhow!("Invalid Safe network peer address: {}", err)).unwrap();
    info!("Safe network to be contacted: [{}]", network_peer_addr);

    let app_config = AppConfig{
        bind_socket_addr,
        static_dir,
        network_peer_addr
    };

    Ok(app_config)
}

async fn get_safe_data_stream(path: web::Path<(String, String)>, files_api_data: Data<FilesApi>, client_data: Data<Client>) -> impl Responder {
    let (config_addr, mut relative_path) = path.into_inner();
    let files_api = files_api_data.get_ref();
    let client = client_data.get_ref();

    info!("config_addr [{}], relative_path [{}]", config_addr, relative_path);

    // load config from path root
    let config = match get_config(client.clone(), files_api.clone(), config_addr).await {
        Ok(value) => value,
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("Failed to load config from map [{:?}]", err)),
    };

    // resolve route
    let relative_path = match resolve_route(relative_path, config.clone()) {
        Ok(value) => value,
        Err(err) => return HttpResponse::InternalServerError()
            .body(format!("Failed to resolve route [{:?}]", err)),
    };

    // resolve file name
    let (is_resolved_file_name, chunk_address) = resolve_file_name(config, relative_path);

    // get xor_name from either DNS or raw
    let xor_name = match resolve_xor_name(client.clone(), &chunk_address).await  {
        Ok(value) => value,
        Err(err) => return HttpResponse::BadRequest()
            .body(format!("Invalid register or XOR address [{:?}]", err)),
    };

    let mut files_download = FilesDownload::new(files_api.clone());

    let mut chunk_count = 0;
    let mut position = 0;
    #[allow(unused_assignments)]
    let mut bytes_read = 0;
    let data_stream = stream! {
        loop {
            match files_download.download_from(ChunkAddress::new(xor_name), position, STREAM_CHUNK_SIZE).await {
                Ok(data) => {
                    chunk_count += 1;
                    bytes_read = data.len();
                    info!("Read [{}] bytes from file position [{}]", bytes_read, position);
                    yield Ok(data); // Yielding the chunk here
                    if bytes_read < STREAM_CHUNK_SIZE {
                        // If the last data chunk returned is smaller than the stream chunk size
                        // it indicates it is the last chunk in the sequence
                        info!("Last chunk [{}] read - breaking", chunk_count);
                        break;
                    }
                    position += STREAM_CHUNK_SIZE;
                }
                Err(e) => {
                    error!("Error reading file: {}", e);
                    yield Err(e);
                    break;
                }
            }
        }
    };

    // todo: When there is only 1 known chunk, we could use body (with 'content-length: x') instead of
    //       streaming (with 'transfer-encoding: chunked') to improve performance.
    HttpResponse::Ok()
        .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&chunk_address, is_resolved_file_name))]))
        .streaming(data_stream)
    // todo: When the XOR address is not found, return a 404 instead of falling back on ERR_INCOMPLETE_CHUNKED_ENCODING
}

async fn post_safe_data(mut payload: web::Payload, files_api: Data<FilesApi>) -> Result<HttpResponse, Error> {
    info!("Post file");
    let files_api = files_api.get_ref().clone();

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

    info!("Chunking file");
    let (head_address, _data_map, _file_size, chunks_paths) =
        FilesApi::chunk_file(&file_path, &chunk_path, true).expect("failed to chunk file");

    info!("Paying for chunks");
    let mut pay_chunks = Vec::new();
    for (pay_chunk_name, _) in chunks_paths.clone() {
        info!("Paying for chunk: {}", pay_chunk_name.to_string());
        pay_chunks.push(pay_chunk_name.clone());
    }
    let payments = files_api.pay_for_chunks(pay_chunks)
        .await.expect("failed to pay for chunks");
    info!("payments: stored [{}], royalties [{}]", payments.storage_cost, payments.royalty_fees);

    info!("Uploading chunks");
    for (_chunk_name, chunk_path) in chunks_paths {
        let chunk = Chunk::new(Bytes::from(fs::read(chunk_path)?));
        files_api.get_local_payment_and_upload_chunk(chunk, false, None)
            .await.expect("failed to get local payment and upload chunk")
    }

    info!("Successfully uploaded data at [{}]", head_address.to_hex());
    Ok(HttpResponse::Ok()
        .body(head_address.to_hex()))
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

async fn safe_connect(peer: &Multiaddr) -> Result<Client>  {
    // note: this was pulled directly from sn_cli

    println!("Instantiating a SAFE client...");
    let secret_key = get_client_secret_key(&get_client_data_dir_path()?)?;

    let peer_args = PeersArgs{first: false, peers: vec![peer.clone()]};
    let bootstrap_peers = get_peers_from_args(peer_args).await?;

    println!(
        "Connecting to the network with {} peers",
        bootstrap_peers.len(),
    );

    let bootstrap_peers = if bootstrap_peers.is_empty() {
        // empty vec is returned if `local-discovery` flag is provided
        None
    } else {
        Some(bootstrap_peers)
    };

    // get the broadcaster as we want to have our own progress bar.
    let broadcaster = ClientEventsBroadcaster::default();

    let result = Client::new(
        secret_key,
        bootstrap_peers,
        None,
        Some(broadcaster),
    ).await?;
    Ok(result)
}

fn get_client_secret_key(root_dir: &PathBuf) -> Result<SecretKey> {
    // note: this was pulled directly from sn_cli
    // create the root directory if it doesn't exist
    std::fs::create_dir_all(root_dir)?;
    let key_path = root_dir.join(CLIENT_KEY);
    let secret_key = if key_path.is_file() {
        info!("Client key found. Loading from file...");
        let secret_hex_bytes = std::fs::read(key_path)?;
        bls_secret_from_hex(secret_hex_bytes)?
    } else {
        info!("No key found. Generating a new client key...");
        let secret_key = SecretKey::random();
        std::fs::write(key_path, hex::encode(secret_key.to_bytes()))?;
        secret_key
    };
    Ok(secret_key)
}

fn get_client_data_dir_path() -> Result<PathBuf> {
    // note: this was pulled directly from sn_cli
    let mut home_dirs = dirs_next::data_dir().expect("Data directory is obtainable");
    home_dirs.push("safe");
    home_dirs.push("client");
    std::fs::create_dir_all(home_dirs.as_path())?;
    info!("home_dirs.as_path(): {}", home_dirs.to_str().unwrap());
    Ok(home_dirs)
}

async fn resolve_xor_name(client: Client, chunk_address: &String) -> Result<XorName> {
    let xor_name = if is_xor(&chunk_address) {
        // use the XOR address directly
        match str_to_xor_name(&chunk_address) {
            Ok(data) => data,
            Err(err) => return Err(err)
        }
    } else {
        // get current XOR address from the register
        match resolve_addr(chunk_address.clone(), false, &client).await {
            Ok(data) => match str_to_xor_name(&data) {
                Ok(data) => data,
                Err(err) => return Err(err)
            }
            Err(err) => return Err(err)
        }
    };
    Ok(xor_name)
}

fn str_to_xor_name(str: &String) -> Result<XorName> {
    let path = Path::new(str);
    let hex_xorname = path
        .file_name()
        .expect("Uploaded file to have name")
        .to_str()
        .expect("Failed to convert path to string");
    let bytes = hex::decode(hex_xorname)?;
    let xor_name_bytes: [u8; 32] = bytes
        .try_into()
        .expect("Failed to parse XorName from hex string");
    Ok(XorName(xor_name_bytes))
}

fn is_xor(safe_url: &String) -> bool {
    // todo: update when NRS (dynamic XOR URL lookup) is available
    return safe_url.len() == 64
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

async fn resolve_addr(addr: String, use_name: bool, client: &Client) -> Result<String> {
    let (address, printing_name) = parse_addr(DNS1, use_name, client.signer_pk())?;

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

    match client.get_register(address).await {
        Ok(register) => {
            info!("Successfully retrieved DNS register [{}]", printing_name);

            let entries = register.clone().read();

            // print all entries
            for entry in entries.clone() {
                let (hash, entry_data) = entry.clone();
                let data_str = String::from_utf8(entry_data.clone()).unwrap_or_else(|_| format!("{entry_data:?}"));
                info!("Entry - hash [{}], data: [{}]", hash, data_str);

                let Some((name, data)) = data_str.split_once(',') else { continue };
                if name == addr {
                    info!("Found DNS entry - name [{}], data: [{}]", name, data);
                    let (dns_address, _) = parse_addr(&data, false, client.signer_pk())?;
                    match client.get_register(dns_address).await {
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
    address_str: &str,
    use_name: bool,
    pk: PublicKey,
) -> Result<(RegisterAddress, String)> {
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

async fn get_config(client: Client, files_api: FilesApi, config_addr: String) -> Result<Config> {
    if config_addr != SAFE_PATH {
        let mut files_download = FilesDownload::new(files_api.clone());

        let xor_name = resolve_xor_name(client.clone(), &config_addr).await?;

        let chunk_addr = ChunkAddress::new(xor_name);
        let data = files_download.download_file(chunk_addr, None).await?;

        let json = String::from_utf8(data.to_vec()).unwrap_or(String::new());
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

fn resolve_file_name(config: Config, relative_path: String) -> (bool, String) {
    if config.file_map.contains_key(&relative_path) {
        let entry = config.file_map.get(&relative_path).expect("Failed to retrieve path from map").to_string();
        info!("file mapper resolved path [{}] to chunk_address [{}]", relative_path, entry);
        return (true, entry)
    }
    (false, relative_path)
}