use clap::Parser;
use oyster::{get_attestation_doc, verify};
use std::error::Error;
use std::fs::File;
use std::io::Write;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// endpoint of the attestation server (http://<ip:port>)
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// path to public key file
    #[arg(long)]
    public: String,

    /// expected pcr0
    #[arg(long)]
    pcr0: String,

    /// expected pcr1
    #[arg(long)]
    pcr1: String,

    /// expected pcr2
    #[arg(long)]
    pcr2: String,

    /// maximum age of attestation (in milliseconds)
    #[arg(short, long)]
    max_age: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let pcrs: [[u8; 48]; 3] = [
        hex::decode(cli.pcr0)?.as_slice().try_into()?,
        hex::decode(cli.pcr1)?.as_slice().try_into()?,
        hex::decode(cli.pcr2)?.as_slice().try_into()?,
    ];
    let attestation_doc = get_attestation_doc(cli.endpoint.parse()?).await?;

    let pub_key = verify(attestation_doc, pcrs, cli.max_age)?;
    println!("verification successful with pubkey: {:?}", pub_key);

    let mut file = File::create(cli.public)?;
    file.write_all(pub_key.as_slice())?;

    Ok(())
}
