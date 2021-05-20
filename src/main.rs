use actix_web::{get, web, App, HttpResponse, HttpServer, Responder, middleware::Logger, Error};
use actix_web::http::header::{CacheControl, CacheDirective};
use actix_files;
use anyhow::{anyhow, Result};
use sn_api::{fetch::SafeData, BootstrapConfig, Safe, SafeUrl};
use log::{info, error, debug};
use std::net::SocketAddr;
use std::env::args;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct AppConfig {
    bind_socket_addr: SocketAddr,
    static_dir: String,
    network_socket_addr: SocketAddr,
}

#[derive(Serialize, Deserialize)]
struct BlobMessage {
    content: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info"); // todo: take from env variable (ignoring currently!)
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    // todo: only call read_args once
    HttpServer::new(|| {
        let logger = Logger::default();

        App::new()
            .wrap(logger)
            .service(get_blob)
            .service(static_file)
            .route("/", web::get().to(angular_route))
            .route("/{path1}/{path2}", web::get().to(angular_route))
            .route("/{path1}/{path2}/{path3}", web::get().to(angular_route))
            .route("/{path1}/{path2}/{path3}/{path4}", web::get().to(angular_route))
            .service(actix_files::Files::new("/static", read_args().static_dir))
            .data(read_args())
    })
        .bind(read_args().bind_socket_addr)?
        .run()
        .await
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

#[get("/blob/{xor}")]
async fn get_blob(path: web::Path<String>, app_config: web::Data<AppConfig>) -> impl Responder {
    let safe_path = path.into_inner();
    let safe_url = format!("safe://{}", safe_path);

    return match fetch_network_blob(app_config.network_socket_addr, &safe_url).await {
        Ok(SafeData::PublicBlob { data, .. }) => {
            info!("Successfully retrieved Blob data at [{}]", safe_url);

            // todo: improve caching defaults

            let mut max_age = 30; // only cache for 30s, as not immutable
            if SafeUrl::from_xorurl(&safe_url).is_ok() {
                info!("URL is XOR URL (treat as immutable): [{}]", safe_url);
                // cache 'forever' when XOR URL (immutable!)
                max_age = 31536000u32;
            }

            HttpResponse::Ok()
            .insert_header(CacheControl(vec![CacheDirective::MaxAge(max_age)]))
            .body(data)
        }
        Ok(other) => {
            error!("Failed to retrieve Blob at [{}], instead obtained: {:?}", safe_url, other);
            HttpResponse::BadRequest().body(format!("Failed to retrieve Blob, instead obtained: {:?}", other))
        },
        Err(err) => {
            error!("Failed to retrieve Blob at [{}]: {:?}", safe_url, err);
            HttpResponse::NotFound().body(format!("Failed to retrieve Blob: {:?}", err))
        },
    }
}

async fn fetch_network_blob(network_addr: SocketAddr, url: &str) -> Result<SafeData> {
    let mut safe = Safe::default();

    let bootstrap_contacts: BootstrapConfig = vec![network_addr].into_iter().collect();

    safe.connect(None, None, Some(bootstrap_contacts)).await?;

    debug!("Connected to Safe!");

    Ok(safe.fetch(&url, None).await?)
}

fn read_args() -> AppConfig {
    // Skip executable name form args
    let mut args_received = args();
    args_received.next();

    // Read the network contact socket address from first arg passed
    let bind_addr = args_received
        .next()
        .ok_or_else(|| anyhow!("No bind address provided")).unwrap();
    let bind_socket_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|err| anyhow!("Invalid bind socket address: {}", err)).unwrap();
    info!("Bind address [{}]", bind_socket_addr);

    // Read the network contact socket address from first arg passed
    let static_dir = args_received
        .next()
        .ok_or_else(|| anyhow!("No static dir provided")).unwrap();
    info!("Static file directory: [{}]", static_dir);

    // Read the network contact socket address from first arg passed
    let network_contact = args_received
        .next()
        .ok_or_else(|| anyhow!("No Safe network contact socket address provided")).unwrap();
    let network_socket_addr: SocketAddr = network_contact
        .parse()
        .map_err(|err| anyhow!("Invalid Safe network contact socket address: {}", err)).unwrap();
    info!("Safe network to be contacted: [{}]", network_socket_addr);

    let app_config = AppConfig{
        bind_socket_addr,
        static_dir,
        network_socket_addr
    };

    app_config
}
