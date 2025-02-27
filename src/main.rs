mod autonomi;
mod anttp_config;
mod caching_client;
mod app_config;
mod archive_helper;
mod xor_helper;
mod archive_client;
mod file_client;

use actix_web::{web, App, HttpServer, Responder, middleware::Logger, HttpRequest};
use actix_files::Files;
use log::{info};
use ::autonomi::Client;
use ::autonomi::Network::ArbitrumSepolia;
use actix_web::dev::{ConnectionInfo};
use actix_web::web::Data;
use ant_evm::EvmWallet;
use awc::Client as AwcClient;
use crate::autonomi::Autonomi;
use crate::caching_client::CachingClient;
use crate::anttp_config::AntTpConfig;
use crate::archive_client::ArchiveClient;
use crate::file_client::FileClient;
use crate::xor_helper::XorHelper;

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
    let xor_helper = XorHelper::new();
    let (archive_addr, archive_file_name) = xor_helper.assign_path_parts(path_parts.clone());

    let autonomi_client = autonomi_client_data.get_ref().clone();
    let caching_autonomi_client = CachingClient::new(autonomi_client.clone());
    let (is_found, archive, is_archive, xor_addr) = xor_helper.resolve_archive_or_file(&caching_autonomi_client, &archive_addr, &archive_file_name).await;
    let file_client = FileClient::new(autonomi_client.clone(), xor_helper.clone(), conn);

    if !is_archive {
        info!("Retrieving file from XOR [{:x}]", xor_addr);
        file_client.get_data(path_parts, request, xor_addr, is_found).await
    } else {
        info!("Retrieving file from archive [{:x}]", xor_addr);
        let archive_client = ArchiveClient::new(caching_autonomi_client.clone(), file_client, xor_helper);
        archive_client.get_data(archive, xor_addr, request, path_parts).await
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
    let xor_helper = XorHelper::new();
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
    } else if xor_helper.is_xor(&hostname.to_string()) {
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