use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use h3::server::RequestStream;
use h3::{
    ext::Protocol,
    quic::{self, RecvDatagramExt, SendDatagramExt, SendStreamUnframed},
    server::Connection,
};
use h3_webtransport::{
    server::{self, WebTransportSession},
    stream,
};
use mem3u8::{cache::RingBuffer, store::Store};

use http::{Method, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use pki_types::{CertificateDer, PrivateKeyDer};
use regex::Regex;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::{fs::File, io, io::BufReader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::pin;
use tokio::sync::watch;
use tokio::time::{sleep, Duration, Instant};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

pub struct HyperHls {
    ssl_path: String,
    ssl_port: u16,
    node_name: String,
    fmp4_cache: Arc<RingBuffer>,
    m3u8_cache: Arc<Store>,
}

impl HyperHls {
    pub fn new(
        ssl_path: String,
        ssl_port: u16,
        fmp4_cache: Arc<RingBuffer>,
        m3u8_cache: Arc<Store>,
        node_name: String,
    ) -> Self {
        Self {
            ssl_path,
            ssl_port,
            fmp4_cache,
            m3u8_cache,
            node_name,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        {
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);

            let crt_path = format!("{}/{}", self.ssl_path, "cert.pem");
            let key_path = format!("{}/{}", self.ssl_path, "privkey.pem");

            let crt_path = Path::new(&crt_path);
            let key_path = Path::new(&key_path);

            let certs = load_certs(crt_path).unwrap();
            let key = load_keys(key_path).unwrap();

            let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            server_config.alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

            println!("Starting to serve on https://{}", addr);
            let ssl_port = self.ssl_port;
            let srv_h2 = {
                let m3u8_cache = Arc::clone(&self.m3u8_cache);
                let fmp4_cache = Arc::clone(&self.fmp4_cache);

                let mut shutdown_signal = rx.clone();
                async move {
                    let incoming = TcpListener::bind(&addr).await.unwrap();
                    let service = service_fn(move |req| {
                        handle_request_h2(
                            req,
                            Arc::clone(&fmp4_cache),
                            Arc::clone(&m3u8_cache),
                            ssl_port,
                        )
                    });

                    loop {
                        tokio::select! {
                            _ = shutdown_signal.changed() => {
                                break;
                            }
                            result = incoming.accept() => {
                                let (tcp_stream, _remote_addr) = result.unwrap();
                                let tls_acceptor = tls_acceptor.clone();
                                let service = service.clone();

                                tokio::spawn(async move {
                                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                        Ok(tls_stream) => tls_stream,
                                        Err(err) => {
                                            eprintln!("failed to perform tls handshake: {err:#}");
                                            return;
                                        }
                                    };
                                    if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(tls_stream), service)
                                        .await
                                    {
                                        eprintln!("failed to serve connection: {err:#}");
                                    }
                                });
                            }
                        }
                    }
                }
            };

            tokio::spawn(srv_h2);
        }

        let certs =
            Certificate(std::fs::read(format!("{}/{}", self.ssl_path, "cert.der")).unwrap());
        let key =
            PrivateKey(std::fs::read(format!("{}/{}", self.ssl_path, "privkey.der")).unwrap());

        let mut tls_config = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certs], key)
            .unwrap();

        tls_config.max_early_data_size = u32::MAX;
        let alpn: Vec<Vec<u8>> = vec![
            b"h3".to_vec(),
            b"h3-32".to_vec(),
            b"h3-31".to_vec(),
            b"h3-30".to_vec(),
            b"h3-29".to_vec(),
        ];
        tls_config.alpn_protocols = alpn;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
        let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();

        let srv_h3 = {
            let m3u8_cache = Arc::clone(&self.m3u8_cache);
            let fmp4_cache = Arc::clone(&self.fmp4_cache);
            let mut shutdown_signal = rx.clone();

            async move {
                loop {
                    tokio::select! {
                        _ = shutdown_signal.changed() => {
                                break;
                        }
                        res = endpoint.accept()  => {
                            if let Some(new_conn) = res {
                                info!("New connection being attempted");

                                let m3u8_cache = Arc::clone(&m3u8_cache);
                                let fmp4_cache = Arc::clone(&fmp4_cache);
                                tokio::spawn(async move {
                                    match new_conn.await {
                                        Ok(conn) => {
                                            let h3_conn = h3::server::builder()
                                                .enable_webtransport(true)
                                                .enable_connect(true)
                                                .enable_datagram(true)
                                                .max_webtransport_sessions(1)
                                                .send_grease(true)
                                                .build(h3_quinn::Connection::new(conn))
                                                .await
                                                .unwrap();

                                                tokio::spawn(async move {
                                                    if let Err(err) = handle_connection(h3_conn, m3u8_cache, fmp4_cache).await {
                                                        tracing::error!("Failed to handle connection: {err:?}");
                                                    }
                                                });

                                                                                }
                                        Err(err) => {
                                            error!("accepting connection failed: {:?}", err);
                                        }

                                    }
                                });
                            }
                        }
                    }
                }
            }
        };

        tokio::spawn(srv_h3);

        Ok(tx)
    }
}

async fn handle_connection(
    mut conn: Connection<h3_quinn::Connection, Bytes>,
    m3u8_cache: Arc<Store>,
    fmp4_cache: Arc<RingBuffer>,
) -> Result<()> {
    loop {
        match conn.accept().await {
            Ok(Some((req, stream))) => {
                let ext = req.extensions();
                match req.method() {
                    &Method::CONNECT if ext.get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT) => {
                        tracing::info!("Peer wants to initiate a webtransport session");
                        tracing::info!("Handing over connection to WebTransport");
                        let session = WebTransportSession::accept(req, stream, conn).await?;
                        tracing::info!("Established webtransport session");
                        // 4. Get datagrams, bidirectional streams, and unidirectional streams and wait for client requests here.
                        // h3_conn needs to handover the datagrams, bidirectional streams, and unidirectional streams to the webtransport session.
                        handle_session_and_echo_all_inbound_messages(session).await?;
                        return Ok(());
                    }
                    _ => {
                        let m3u8_cache = Arc::clone(&m3u8_cache);
                        let fmp4_cache = Arc::clone(&fmp4_cache);
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_request_h3(req, stream, fmp4_cache, m3u8_cache).await
                            {
                                error!("handling request failed: {}", e);
                            }
                        });
                        return Ok(());
                    }
                }
            }
            Ok(None) => {
                break;
            }
            Err(err) => {
                error!("error on accept {}", err);
                break;
            }
        }
    }

    Ok(())
}

async fn get_m3u8(
    m3u8_cache: Arc<Store>,
    path: u64,
    msn: usize,
    idx: usize,
) -> Option<(Bytes, u64)> {
    let timeout = Duration::from_secs(3);
    let start_time = Instant::now();
    let poll_interval = Duration::from_millis(5);

    while start_time.elapsed() < timeout {
        {
            if let Some(data) = m3u8_cache.get(path, msn, idx) {
                return Some(data.clone());
            }
            if let Some(data) = m3u8_cache.get(path, msn + 1, 0) {
                return Some(data.clone());
            }
        }

        sleep(poll_interval).await;
    }

    None
}

async fn get_seg(
    fmp4_cache: Arc<RingBuffer>,
    m3u8_cache: Arc<Store>,
    path: u64,
    id: usize,
) -> Option<(Bytes, u64)> {
    if let Some(idxs) = m3u8_cache.get_idxs(path, id) {
        let mut buf = Vec::new();
        for n in idxs.0..idxs.1 {
            if let Some(data) = fmp4_cache.get(path, n) {
                buf.extend_from_slice(&data.0);
            } else {
                return None; // Part missing, return None
            }
        }

        let h = const_xxh3(&buf);
        let buf = Bytes::from(buf);
        Some((buf, h))
    } else {
        None
    }
}

async fn get_part(fmp4_cache: Arc<RingBuffer>, path: u64, id: usize) -> Option<(Bytes, u64)> {
    let timeout = Duration::from_secs(3);
    let start_time = Instant::now();
    let poll_interval = Duration::from_millis(1);

    while start_time.elapsed() < timeout {
        if let Some(data) = fmp4_cache.get(path, id) {
            return Some(data.clone());
        }

        sleep(poll_interval).await;
    }

    None
}

fn detect_content_type(file_name: &str) -> &'static str {
    if file_name.ends_with(".m3u8") {
        "application/vnd.apple.mpegurl"
    } else if file_name.ends_with(".mp4") {
        "video/mp4"
    } else if file_name.ends_with(".jpeg") {
        "image/jpeg"
    } else {
        ""
    }
}

fn extract_id(s: &str) -> Option<usize> {
    let re = Regex::new(r"(s|p)(\d+)(\.mp4)$").unwrap();
    re.captures(s).and_then(|caps| {
        if let Some(id_match) = caps.get(2) {
            let id = usize::from_str(id_match.as_str()).ok()?;
            Some(id)
        } else {
            None
        }
    })
}

async fn handle_request_h2(
    req: http::Request<Incoming>,
    fmp4_cache: Arc<RingBuffer>,
    m3u8_cache: Arc<Store>,
    ssl_port: u16,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let (status, data, content_type) = request_handler(
        req.method(),
        req.uri().path(),
        req.uri().query(),
        fmp4_cache.clone(),
        m3u8_cache.clone(),
    )
    .await?;
    if let (Some(data), Some(content_type)) = (data, content_type) {
        let mut response = Response::new(Full::from(data.0));
        *response.status_mut() = status;
        response.headers_mut().insert(
            "alt-srv",
            format!("h3=\":{}\"; ma=2592000", ssl_port).parse().unwrap(),
        );
        response
            .headers_mut()
            .insert("content-type", content_type.parse().unwrap());
        response
            .headers_mut()
            .insert("etag", format!("{}", data.1).parse().unwrap());

        if content_type == "application/vnd.apple.mpegurl" {
            response
                .headers_mut()
                .insert("content-encoding", "gzip".parse().unwrap());
            response
                .headers_mut()
                .insert("vary", "accept-encoding".parse().unwrap());
        }
        Ok(response)
    } else {
        let mut response = Response::new(Full::default());
        *response.status_mut() = status;
        response.headers_mut().insert(
            "alt-srv",
            format!("h3=\":{}\"; ma=2592000", ssl_port).parse().unwrap(),
        );
        Ok(response)
    }
}

async fn handle_request_h3(
    req: http::Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    fmp4_cache: Arc<RingBuffer>,
    m3u8_cache: Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (status, data, content_type) = request_handler(
        req.method(),
        req.uri().path(),
        req.uri().query(),
        fmp4_cache,
        m3u8_cache,
    )
    .await?;

    if let (Some(data), Some(content_type)) = (data, content_type) {
        let mut r = http::Response::builder()
            .status(status)
            .header("content-type", content_type.clone())
            .header("etag", data.1);
        if content_type == "application/vnd.apple.mpegurl" {
            r = r
                .header("content-encoding", "gzip")
                .header("vary", "accept-encoding");
        }
        let resp = r.body(()).unwrap();

        match stream.send_response(resp).await {
            Ok(_) => {}
            Err(err) => {
                error!("unable to send response to connection peer: {:?}", err);
            }
        }

        stream.send_data(data.0).await?;
    } else {
        let resp = http::Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();

        match stream.send_response(resp).await {
            Ok(_) => {}
            Err(err) => {
                error!("unable to send response to connection peer: {:?}", err);
            }
        }
    }

    Ok(stream.finish().await?)
}

async fn request_handler(
    method: &Method,
    path: &str,
    query: Option<&str>,
    fmp4_cache: Arc<RingBuffer>,
    m3u8_cache: Arc<Store>,
) -> Result<
    (StatusCode, Option<(Bytes, u64)>, Option<String>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let res = match (method, path) {
        (&Method::OPTIONS, _) => (StatusCode::OK, None, None),

        (&Method::GET, path) => {
            let keys: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

            if keys.is_empty() {
                (StatusCode::NOT_FOUND, None, None)
            } else if keys[0] == "up" {
                (
                    StatusCode::OK,
                    Some((Bytes::from("OK"), 0)),
                    Some("text/plain".into()),
                )
            } else if keys[0] == "play" {
                let contents = include_str!("./public/index.html");
                (
                    StatusCode::OK,
                    Some((Bytes::from(contents), 0)),
                    Some("text/html".into()),
                )
            } else if keys[0] == "hls.min.js" {
                let contents = include_str!("./public/hls.min.js");
                (
                    StatusCode::OK,
                    Some((Bytes::from(contents), 0)),
                    Some("text/javascript".into()),
                )
            } else if keys.len() > 1 {
                let ct = detect_content_type(&keys[1]);
                if ct.is_empty() {
                    (StatusCode::NOT_FOUND, None, None)
                } else {
                    let stream_id = keys[0].parse::<u64>()?;
                    let mut params: HashMap<&str, &str> = HashMap::new();
                    let mut data: Option<(Bytes, u64)> = None;
                    let content_type = Some(ct.to_string());

                    if let Some(query) = query {
                        query.split('&').for_each(|part| {
                            let mut split = part.splitn(2, '=');
                            if let (Some(key), Some(value)) = (split.next(), split.next()) {
                                params.insert(key, value);
                            }
                        });

                        if let (Some(msn_str), Some(part_str)) =
                            (params.get("_HLS_msn"), params.get("_HLS_part"))
                        {
                            if let (Ok(msn_num), Ok(part_num)) =
                                (msn_str.parse::<usize>(), part_str.parse::<usize>())
                            {
                                if let Some(res) =
                                    get_m3u8(m3u8_cache.clone(), stream_id, msn_num, part_num).await
                                {
                                    data = Some(res);
                                }
                            }
                        } else if params.get("_HLS_skip").is_some() {
                            if let Some(res) = m3u8_cache.last(stream_id) {
                                data = Some(res)
                            }
                        }
                    } else if keys[1] == "stream.m3u8" {
                        if let Some(res) = m3u8_cache.last(stream_id) {
                            data = Some(res)
                        }
                    } else if keys[1].starts_with("s") {
                        if let Some(id) = extract_id(&keys[1]) {
                            if let Some(res) =
                                get_seg(fmp4_cache.clone(), m3u8_cache.clone(), stream_id, id).await
                            {
                                data = Some(res)
                            }
                        }
                    } else if keys[1].starts_with("p") {
                        if let Some(id) = extract_id(&keys[1]) {
                            if let Some(res) = get_part(fmp4_cache.clone(), stream_id, id).await {
                                data = Some(res)
                            }
                        }
                    } else if keys[1].starts_with("init.mp4") {
                        if let Some(d) = m3u8_cache.get_init(stream_id) {
                            data = Some((d, 0));
                        }
                    }

                    if let Some(data) = data {
                        (StatusCode::OK, Some(data), content_type)
                    } else {
                        (StatusCode::NOT_FOUND, None, None)
                    }
                }
            } else {
                (StatusCode::NOT_FOUND, None, None)
            }
        }
        _ => (StatusCode::NOT_FOUND, None, None),
    };

    Ok(res)
}

fn add_cors_headers(res: &mut http::Response<http_body_util::Full<Bytes>>) {
    res.headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    res.headers_mut().insert(
        "access-control-allow-methods",
        "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
    );
    res.headers_mut().insert(
        "access-control-allow-headers",
        "Content-Type".parse().unwrap(),
    );
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .next()
        .unwrap()
        .map(Into::into)
}

macro_rules! log_result {
    ($expr:expr) => {
        if let Err(err) = $expr {
            tracing::error!("{err:?}");
        }
    };
}

async fn echo_stream<T, R>(send: T, recv: R) -> anyhow::Result<()>
where
    T: AsyncWrite,
    R: AsyncRead,
{
    pin!(send);
    pin!(recv);

    tracing::info!("Got stream");
    let mut buf = Vec::new();
    recv.read_to_end(&mut buf).await?;

    let message = Bytes::from(buf);

    send_chunked(send, message).await?;

    Ok(())
}

// Used to test that all chunks arrive properly as it is easy to write an impl which only reads and
// writes the first chunk.
async fn send_chunked(mut send: impl AsyncWrite + Unpin, data: Bytes) -> anyhow::Result<()> {
    for chunk in data.chunks(4) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        tracing::info!("Sending {chunk:?}");
        send.write_all(chunk).await?;
    }

    Ok(())
}

async fn open_bidi_test<S>(mut stream: S) -> anyhow::Result<()>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    tracing::info!("Opening bidirectional stream");

    stream
        .write_all(b"Hello from a server initiated bidi stream")
        .await
        .context("Failed to respond")?;

    let mut resp = Vec::new();
    stream.shutdown().await?;
    stream.read_to_end(&mut resp).await?;

    tracing::info!("Got response from client: {resp:?}");

    Ok(())
}

/// This method will echo all inbound datagrams, unidirectional and bidirectional streams.
#[tracing::instrument(level = "info", skip(session))]
async fn handle_session_and_echo_all_inbound_messages<C>(
    session: WebTransportSession<C, Bytes>,
) -> anyhow::Result<()>
where
    // Use trait bounds to ensure we only happen to use implementation that are only for the quinn
    // backend.
    C: 'static
        + Send
        + h3::quic::Connection<Bytes>
        + RecvDatagramExt<Buf = Bytes>
        + SendDatagramExt<Bytes>,
    <C::SendStream as h3::quic::SendStream<Bytes>>::Error:
        'static + std::error::Error + Send + Sync + Into<std::io::Error>,
    <C::RecvStream as h3::quic::RecvStream>::Error:
        'static + std::error::Error + Send + Sync + Into<std::io::Error>,
    stream::BidiStream<C::BidiStream, Bytes>:
        quic::BidiStream<Bytes> + Unpin + AsyncWrite + AsyncRead,
    <stream::BidiStream<C::BidiStream, Bytes> as quic::BidiStream<Bytes>>::SendStream:
        Unpin + AsyncWrite + Send + Sync,
    <stream::BidiStream<C::BidiStream, Bytes> as quic::BidiStream<Bytes>>::RecvStream:
        Unpin + AsyncRead + Send + Sync,
    C::SendStream: Send + Unpin,
    C::RecvStream: Send + Unpin,
    C::BidiStream: Send + Unpin,
    stream::SendStream<C::SendStream, Bytes>: AsyncWrite,
    C::BidiStream: SendStreamUnframed<Bytes>,
    C::SendStream: SendStreamUnframed<Bytes>,
{
    let session_id = session.session_id();

    // This will open a bidirectional stream and send a message to the client right after connecting!
    let stream = session.open_bi(session_id).await?;

    tokio::spawn(async move { log_result!(open_bidi_test(stream).await) });

    loop {
        tokio::select! {
            datagram = session.accept_datagram() => {
                let datagram = datagram?;
                if let Some((_, datagram)) = datagram {
                    tracing::info!("Responding with {datagram:?}");
                    // Put something before to make sure encoding and decoding works and don't just
                    // pass through
                    let mut resp = BytesMut::from(&b"Response: "[..]);
                    resp.put(datagram);

                    session.send_datagram(resp.freeze())?;
                    tracing::info!("Finished sending datagram");
                }
            }
            uni_stream = session.accept_uni() => {
                let (id, stream) = uni_stream?.unwrap();

                let send = session.open_uni(id).await?;
                tokio::spawn( async move { log_result!(echo_stream(send, stream).await); });
            }
            stream = session.accept_bi() => {
                if let Some(server::AcceptedBi::BidiStream(_, stream)) = stream? {
                    let (send, recv) = quic::BidiStream::split(stream);
                    tokio::spawn( async move { log_result!(echo_stream(send, recv).await); });
                }
            }
            else => {
                break
            }
        }
    }

    tracing::info!("Finished handling session");

    Ok(())
}
