use crate::{
    config::ServerConfig,
    error::{H2Error, ServerError, ServerResult},
    traits::Router,
};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::Response;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tls_helpers::tls_acceptor_from_base64;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

pub struct Http2Server {
    config: ServerConfig,
    router: Arc<dyn Router>,
}

impl Http2Server {
    pub fn new(config: ServerConfig, router: Arc<dyn Router>) -> Self {
        Self { config, router }
    }

    pub async fn start(&self, mut shutdown_rx: watch::Receiver<()>) -> ServerResult<()> {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.config.port);
        let tls_acceptor = tls_acceptor_from_base64(
            &self.config.cert_pem_base64,
            &self.config.privkey_pem_base64,
            false,
            true,
        )
        .map_err(|e| ServerError::Tls(e.to_string()))?;

        let listener = TcpListener::bind(addr).await.map_err(ServerError::Io)?;
        info!("HTTP/2 server listening at {}", addr);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("HTTP/2 server shutting down");
                    break;
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _peer)) => {
                            let tls_acceptor = tls_acceptor.clone();
                            let router = Arc::clone(&self.router);
                            let port = self.config.port;

                            tokio::spawn(async move {
                                let tls_stream = match tls_acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("TLS handshake failed: {}", e);
                                        return;
                                    }
                                };

                                let service = service_fn(move |req: http::Request<Incoming>| {
                                    let router = Arc::clone(&router);
                                    async move {
                                        match handle_h2_request(req, router, port).await {
                                            Ok(resp) => Ok(resp),
                                            Err(e) => {
                                                error!("Request handling error: {}", e);
                                                Err("request failed")
                                            }
                                        }
                                    }
                                });

                                if let Err(e) = ConnectionBuilder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
                                    .await
                                {
                                    error!("Serving HTTP/2 connection failed: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept failed: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_h2_request(
    req: http::Request<Incoming>,
    router: Arc<dyn Router>,
    port: u16,
) -> Result<Response<Full<Bytes>>, H2Error> {
    let (parts, _body) = req.into_parts();
    let req = http::Request::from_parts(parts, ());

    let handler_response = router.route(req).await.map_err(H2Error::Router)?;

    let mut response = Response::new(Full::from(handler_response.body.unwrap_or_else(Bytes::new)));
    *response.status_mut() = handler_response.status;

    response.headers_mut().insert(
        HeaderName::from_static("alt-srv"),
        HeaderValue::from_str(&format!("h3=\":{}\"; ma=2592000", port))?,
    );

    if let Some(ct) = handler_response.content_type {
        response.headers_mut().insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_str(&ct)?,
        );
    }
    if let Some(etag) = handler_response.etag {
        response.headers_mut().insert(
            HeaderName::from_static("etag"),
            HeaderValue::from_str(&etag.to_string())?,
        );
    }
    for (k, v) in handler_response.headers {
        response
            .headers_mut()
            .insert(k.parse::<HeaderName>()?, v.parse::<HeaderValue>()?);
    }

    add_cors_headers(&mut response);

    Ok(response)
}

fn add_cors_headers(res: &mut Response<Full<Bytes>>) {
    res.headers_mut().insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("*"),
    );
}
