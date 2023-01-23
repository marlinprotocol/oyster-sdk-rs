use clap::Parser;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use tokio;
use oyster::{get_attestation_doc, verify};


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// endpoint of the attestation server (http://<ip:port>)
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// path to public key file
    #[arg(short, long)]
    public: String,

    /// expected pcr0
    #[arg(short, long)]
    pcr0: String,

    /// expected pcr1
    #[arg(short, long)]
    pcr1: String,

    /// expected pcr2
    #[arg(short, long)]
    pcr2: String,

    /// minimum cpus
    #[arg(short, long)]
    min_cpus: usize,

    /// minimum memory
    #[arg(short, long)]
    min_mem: usize,

    /// maximum age of attestation (in milliseconds)
    #[arg(short, long)]
    max_age: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let pcrs = vec![cli.pcr0, cli.pcr1, cli.pcr2];
    let attestation_doc = get_attestation_doc(cli.endpoint.parse()?).await?;

    let pub_key = verify(attestation_doc, pcrs, cli.min_cpus, cli.min_mem, cli.max_age)?;
    println!("verification successful with pubkey: {:?}", pub_key);

    let mut file = File::create(cli.public)?;
    file.write_all(pub_key.as_slice())?;

    Ok(())
}

