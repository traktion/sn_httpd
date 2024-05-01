use actix_web::{Error, error, HttpRequest, HttpResponse, web};
use actix_web::dev::PeerAddr;
use awc::Client;

#[derive(Clone)]
pub struct Proxy {
    pub parent_domain: String,
    pub client: Client
}

impl Proxy {
    pub fn new(parent_domain: String, client: Client) -> Self {
        Self {
            parent_domain,
            client
        }
    }

    pub fn is_remote_url(&self, hostname: &str) -> bool {
        !hostname.ends_with(&self.parent_domain)
    }

    /// Forwards the incoming HTTP request using `awc`.
    pub async fn forward(
        &self,
        req: HttpRequest,
        payload: web::Payload,
        peer_addr: Option<PeerAddr>
    ) -> Result<HttpResponse, Error> {
        let forwarded_req = self.client
            .request_from(req.path(), req.head())
            .no_decompress();

        // TODO: This forwarded implementation is incomplete as it only handles the unofficial
        // X-Forwarded-For header but not the official Forwarded one.
        let forwarded_req = match peer_addr {
            Some(PeerAddr(addr)) => {
                forwarded_req.insert_header(("x-forwarded-for", addr.ip().to_string()))
            }
            None => forwarded_req,
        };

        let res = forwarded_req
            .send_stream(payload)
            .await
            .map_err(error::ErrorInternalServerError)?;

        let mut client_resp = HttpResponse::build(res.status());
        // Remove `Connection` as per
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
        for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
            client_resp.insert_header((header_name.clone(), header_value.clone()));
        }

        Ok(client_resp.streaming(res))
    }
}