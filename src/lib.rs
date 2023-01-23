use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use hex;
use openssl::asn1::Asn1Time;
use openssl::x509::{X509VerifyResult, X509};
use serde_cbor::{self, value, value::Value};
use std::collections::BTreeMap;
use std::error::Error;
use hyper::{client::Client, Uri};
use serde_json;
use serde::Deserialize;
use chrono::Utc;


#[derive(Deserialize)]
struct EnclaveConfig {
    total_memory: usize,
    total_cpus : usize
}

fn get_all_certs(cert: X509, cabundle: Vec<Value>) -> Result<Vec<X509>, Box<dyn Error>> {
    let mut all_certs = vec![cert];
    for cert in cabundle {
        let cert = (match cert { Value::Bytes(b) => Ok(b), _ => Err("cert decode failure") })?;
        let cert = X509::from_der(&cert)?;
        all_certs.push(cert);
    }
    Ok(all_certs)
}

fn verify_cert_chain(
    cert: X509,
    cabundle: Vec<Value>,
    root_cert_pem: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let certs = get_all_certs(cert, cabundle)?;

    for i in 0..(certs.len() - 1) {
        let pubkey = certs[i + 1].public_key()?;
        if certs[i].verify(&pubkey)? == false {
            return Err("signature verification failed".into());
        }
        if certs[i + 1].issued(&certs[i]) != X509VerifyResult::OK {
            return Err("certificate issuer and subject verification failed".into());
        }
        let current_time = Asn1Time::days_from_now(0)?;
        if certs[i].not_after() < current_time || certs[i].not_before() > current_time {
            return Err("certificate timestamp expired/not valid".into());
        }
    }

    let root_cert = X509::from_pem(&root_cert_pem)?;
    if &root_cert != certs.last().unwrap() {
        return Err("root certificate mismatch".into());
    }
    Ok(())
}

pub fn verify(
    attestation_doc_cbor: Vec<u8>,
    pcrs: Vec<String>,
    min_cpus: usize,
    min_mem: usize,
    max_age: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // parse attestation doc
    let cosesign1 = CoseSign1::from_bytes(&attestation_doc_cbor)?;
    let payload = cosesign1.get_payload::<Openssl>(None)?;
    let cbor = serde_cbor::from_slice::<Value>(&payload)?;
    let mut attestation_doc = value::from_value::<BTreeMap<Value, Value>>(cbor)?;

    // verify pcrs
    let pcrs_arr = attestation_doc
        .remove(&"pcrs".to_owned().into())
        .ok_or("pcrs key not found in attestation doc".to_owned())?;
    let mut pcrs_arr = value::from_value::<BTreeMap<Value, Value>>(pcrs_arr)?;
    for i in 0u8..3u8 {
        let pcr = pcrs_arr
            .remove(&i.into())
            .ok_or(format!("pcr{i} not found"))?;
        let pcr = (match pcr { Value::Bytes(b) => Ok(b), _ => Err("pcr decode failure") })?;
        if hex::encode(pcr) != pcrs[i as usize] {
            return Err(format!("pcr{i} match failed").into());
        }
    }

    // verify attestation doc signature
    let enclave_certificate = attestation_doc
        .remove(&"certificate".to_owned().into())
        .ok_or("certificate key not found in attestation doc".to_owned())?;
    let enclave_certificate = (match enclave_certificate { Value::Bytes(b) => Ok(b), _ => Err("enclave certificate decode failure") })?;
    let enclave_certificate = X509::from_der(&enclave_certificate)?;
    let pub_key = enclave_certificate.public_key()?;
    let verify_result = cosesign1.verify_signature::<Openssl>(&pub_key)?;

    if !verify_result {
        return Err("cose signature verfication failed".into());
    }

    // verify certificate chain
    let cabundle = attestation_doc
        .remove(&"cabundle".to_owned().into())
        .ok_or("cabundle key not found in attestation doc".to_owned())?;
    let mut cabundle = (match cabundle { Value::Array(b) => Ok(b), _ => Err("cabundle decode failure") })?;
    cabundle.reverse();

    let root_cert_pem = include_bytes!("./aws.cert").to_vec();
    verify_cert_chain(enclave_certificate, cabundle, root_cert_pem)?;

    // verify enclave size
    let user_data = attestation_doc
        .remove(&"user_data".to_owned().into())
        .ok_or("user data not found in attestation doc".to_owned())?;
    let user_data = (match user_data { Value::Bytes(b) => Ok(b), _ => Err("user data decode failure") })?;
    let size = serde_json::from_slice::<EnclaveConfig>(user_data.as_slice())?;
    if size.total_cpus < min_cpus {
        return Err("enclave does not meet minimum cpus requirement".into());
    }
    if size.total_memory < min_mem {
        return Err("enclave does not meet minimum memory requirement".into());
    }

    // verify age
    let timestamp = attestation_doc
        .remove(&"timestamp".to_owned().into())
        .ok_or("timestamp not found in attestation doc".to_owned())?;
    let timestamp = (match timestamp { Value::Integer(b) => Ok(b), _ => Err("timestamp decode failure") })?;
    let now = Utc::now().timestamp_millis();
    println!("{}, {}, {}", (now as i128), (max_age as i128), timestamp);
    if (now as i128) - (max_age as i128) > timestamp {
        return Err("attestation is too old".into());
    }

    // return the enclave key
    let public_key = attestation_doc
        .remove(&"public_key".to_owned().into())
        .ok_or("public key not found in attestation doc".to_owned())?;
    let public_key = (match public_key { Value::Bytes(b) => Ok(b), _ => Err("public key decode failure") })?;

    Ok(public_key)
}

pub async fn get_attestation_doc(endpoint: Uri) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = Client::new();
    let res = client.get(endpoint).await?;
    Ok(hyper::body::to_bytes(res).await?.to_vec())
}

