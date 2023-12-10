use std::error::Error;
use std::time::Duration;

use libsodium_sys::{
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519, crypto_sign_keypair,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

pub use oyster::scallop::*;

async fn server_task(key: [u8; 32]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = TcpListener::bind("127.0.0.1:21000").await?;

    loop {
        let (mut stream, _) = server.accept().await?;

        new_server_async_Noise_XX_25519_ChaChaPoly_BLAKE2s(&mut stream, &key).await?;
    }
}

async fn client_task(key: [u8; 32]) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let mut client = TcpStream::connect("127.0.0.1:21000").await?;

        new_client_async_Noise_XX_25519_ChaChaPoly_BLAKE2s(&mut client, &key).await?;

        println!("Done.");

        sleep(Duration::from_secs(5)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut sign_pk = [0u8; 32];
    let mut sign_sk = [0u8; 64];
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 32];
    unsafe { crypto_sign_keypair(sign_pk.as_mut_ptr(), sign_sk.as_mut_ptr()) };
    unsafe { crypto_sign_ed25519_pk_to_curve25519(pk.as_mut_ptr(), sign_pk.as_mut_ptr()) };
    unsafe { crypto_sign_ed25519_sk_to_curve25519(sk.as_mut_ptr(), sign_sk.as_mut_ptr()) };

    tokio::spawn(server_task(sk));

    sleep(Duration::from_secs(5)).await;
    client_task(sk).await?;

    Ok(())
}
