use http::{Request, Response, StatusCode};
use hyper::{server::conn::Http, service::service_fn, Body};
use libsodium_sys::crypto_sign_keypair;
pub use oyster::MolluskStream;
use std::convert::Infallible;
use std::{error::Error, time::Duration};
use tokio::net::TcpListener;
use tokio::{net::TcpStream, time::sleep};
use tower::ServiceExt;

async fn hello(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("server: hello");
    Ok(Response::new(Body::from("Hello World!")))
}

async fn server_task(key: [u8; 64]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = TcpListener::bind("127.0.0.1:21000").await?;

    loop {
        let (stream, _) = server.accept().await?;

        let ss = MolluskStream::new_server(stream, key).await?;

        println!("{:?}", ss);

        tokio::task::spawn(async move {
            if let Err(http_err) = Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(ss, service_fn(hello))
                .await
            {
                eprintln!("Error while serving HTTP connection: {}", http_err);
            }
        });
    }
}

async fn client_task(pubkey: [u8; 32]) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let client = TcpStream::connect("127.0.0.1:21000").await?;

        let ss = MolluskStream::new_client(client, pubkey).await?;

        println!("{:?}", ss);

        let (mut request_sender, connection) = hyper::client::conn::handshake(ss).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Error in connection: {}", e);
            }
        });

        let request = Request::builder().method("GET").body(Body::from(""))?;
        let response = request_sender.send_request(request).await?;
        assert!(response.status() == StatusCode::OK);
        println!("{:?}", hyper::body::to_bytes(response.into_body()).await?);

        request_sender.ready().await?;
        let request = Request::builder().method("GET").body(Body::from(""))?;
        let response = request_sender.send_request(request).await?;
        assert!(response.status() == StatusCode::OK);
        println!("{:?}", hyper::body::to_bytes(response.into_body()).await?);

        sleep(Duration::from_secs(5)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];
    unsafe { crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };

    tokio::spawn(server_task(sk));

    sleep(Duration::from_secs(5)).await;
    client_task(pk).await?;

    Ok(())
}
