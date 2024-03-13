use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, middleware::Logger, Error};
use actix_web::http::header::{CacheControl, CacheDirective};
use actix_files::Files;
use anyhow::{anyhow};
use xor_name::XorName;
use log::{info, error, warn};
use std::net::SocketAddr;
use std::env::args;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{Bytes, Empty};
use std::path::PathBuf;
use std::path::Path;
use async_stream::stream;
use tokio::sync::Mutex;
use sn_client::transfers::bls::SecretKey;
use sn_client::transfers::bls_secret_from_hex;
use sn_client::{BATCH_SIZE, Client, ClientEvent, ClientEventsBroadcaster, ClientEventsReceiver, FilesApi, FilesDownload, FilesDownloadEvent};
use sn_peers_acquisition::{get_peers_from_args, PeersArgs};
use color_eyre::Result;
use multiaddr::Multiaddr;
use sn_client::protocol::storage::ChunkAddress;

const CLIENT_KEY: &str = "clientkey";

#[derive(Clone)]
struct AppConfig {
    bind_socket_addr: SocketAddr,
    static_dir: String,
    network_peer_addr: Multiaddr,
}

#[derive(Clone, Default)]
struct Accounts {
    accounts: HashMap<String, Site>
}

#[derive(Clone)]
struct Site {
    configurl: String,
    keyxorurl: String,
    //keypair: Keypair,
    credit: i64,
    usage: i64
}

#[derive(Clone)]
struct Urls {
    urls: HashMap<String, Site>
}

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    urls: Vec<String>,
    assets: Vec<String>
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info"); // todo: take from env variable (ignoring currently!)
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let app_config = read_args().expect("Failed to read CLI arguments");
    let bind_socket_addr = app_config.bind_socket_addr;

    /*let accounts = web::Data::new(Mutex::from(Accounts {
        accounts: HashMap::new()
    }));
    let urls = web::Data::new(Mutex::from(Urls {
        urls: HashMap::new()
    }));*/

    // initialise safe network connection and files api
    let client = safe_connect(&app_config.network_peer_addr).await.expect("Failed to connect to Safe Network");
    let data_dir_path = get_client_data_dir_path().expect("Failed to get client data dir path");
    let files_api = FilesApi::build(client.clone(), data_dir_path).expect("Failed to instantiate FilesApi");

    HttpServer::new(move || {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(get_safe_data)
            //.service(get_account)
            .service(static_file)
            .route("/", web::get().to(angular_route))
            .route("/{path1}/{path2}", web::get().to(angular_route))
            .route("/{path1}/{path2}/{path3}", web::get().to(angular_route))
            .route("/{path1}/{path2}/{path3}/{path4}", web::get().to(angular_route))
            .service(Files::new("/static", app_config.static_dir.clone()))
            .app_data(web::Data::new(app_config.clone()))
            .app_data(web::Data::new(files_api.clone()))
            //.app_data(accounts.clone())
            //.app_data(urls.clone())
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

async fn angular_route(app_config: web::Data<AppConfig>) -> Result<actix_files::NamedFile, Error> {
    info!("Route to angular app");
    Ok(actix_files::NamedFile::open( format!("{}/index.html", app_config.static_dir))?)
}

#[get("/{static_file}")]
async fn static_file(path: web::Path<String>, app_config: web::Data<AppConfig>) -> Result<actix_files::NamedFile, Error> {
    info!("Route to angular file");
    Ok(actix_files::NamedFile::open(format!("{}/{}", app_config.static_dir, path.into_inner()))?)
}

#[get("/safe/{xor}")]
async fn get_safe_data(path: web::Path<String>, app_config: web::Data<AppConfig>, files_api: web::Data<FilesApi>) -> impl Responder {
    let xor_str = path.into_inner();
    let xor_name = match str_to_xor_name(&xor_str) {
        Ok(data) => data,
        Err(err) => {
            error!("Failed to parse XOR string [{:?}]", err);
            return HttpResponse::InternalServerError()
                .body(format!("Failed to parse XOR string [{:?}]", err))
        }
    };

    let safe_url = format!("safe://{}", xor_str);

    // todo: implement funding
    /*if !urls.lock().await.urls.contains_key(&safe_url) {
        error!("Funding account has not been created for XOR URL: [{}]", safe_url);
        return HttpResponse::PaymentRequired()
            .body(format!("Funding account has not been created for XOR URL: [{}]", safe_url))
    }
    if let Some(site) = urls.lock().await.urls.get(&safe_url) {
        if site.credit > 0 {
            error!("Insufficient funding on account to retrieve XOR URL: [{}]", safe_url);
            return HttpResponse::PaymentRequired()
                .body(format!("Insufficient funding on account to retrieve XOR URL: [{}]", safe_url))
        }
    }*/

    let mut files_download = FilesDownload::new(files_api.get_ref().clone());

    return match files_download.download_from(ChunkAddress::new(xor_name), 0, usize::MAX).await {
        Ok(data) => {
            info!("Successfully retrieved data at [{}]", safe_url);
            HttpResponse::Ok()
                .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&safe_url))]))
                .body(data)
        }
        Err(err) => {
            warn!("Failed to retrieve data at [{}]: {:?}", safe_url, err);
            HttpResponse::NotFound()
                .body(format!("Failed to retrieve data at [{}]: {:?}", safe_url, err))
        }
    }

    // experimental - instead of downloading to memory, then sending, can we stream parts of the file?

    // todo: get events
    //let mut download_events_rx = files_download.get_events();

    /*let mut position = 0;
    let length = 1024 * 1024;
    let data_stream = stream! {
        loop {
            match files_download.download_from(ChunkAddress::new(xor_name), position, length).await {
                Ok(data) => {
                    /*if data == Empty {
                        break;
                    }*/
                    info!("Read bytes from file position {}", position);
                    position = position + length;
                    yield Ok(data); // Yielding the chunk here
                }
                Err(e) => {
                    error!("Error reading file: {}", e);
                    yield Err(e);
                    break;
                }
            }
        }
    };

    HttpResponse::Ok()
        .insert_header(CacheControl(vec![CacheDirective::MaxAge(calc_cache_max_age(&safe_url))]))
        .streaming(data_stream)*/
}

fn calc_cache_max_age(safe_url: &String) -> u32 {
    31536000u32
    // todo: update when NRS (dynamic XOR URL lookup) is available
    /*return match SafeUrl::from_xorurl(&safe_url) {
        Ok(_) => {
            info!("URL is XOR URL (treat as immutable): [{}]", safe_url);
            31536000u32 // cache 'forever'
        },
        Err(_) => {
            info!("URL is NRS URL (treat as mutable): [{}]", safe_url);
            30 // only cache for 30s
        }
    }*/
}

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
        true, // todo: optimise
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
    Ok(home_dirs)
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
