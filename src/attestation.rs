use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use chrono::Utc;
use hyper::{client::Client, Uri};
use openssl::asn1::Asn1Time;
use openssl::x509::{X509VerifyResult, X509};
use serde::Deserialize;
use serde_cbor::{self, value, value::Value};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct AttestationDecoded {
    pub pcrs: Vec<String>,
    pub total_memory: usize,
    pub total_cpus: usize,
    pub timestamp: usize,
    pub ed25519_public: [u8; 32],
}

#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    #[error("failed to parse: {0}")]
    ParseFailed(String),
    #[error("failed to verify attestation: {0}")]
    VerifyFailed(String),
    #[error("http error")]
    HttpError(#[from] hyper::Error),
}

#[derive(Deserialize)]
struct EnclaveConfig {
    total_memory: usize,
    total_cpus: usize,
}

fn get_all_certs(cert: X509, cabundle: Vec<Value>) -> Result<Vec<X509>, AttestationError> {
    let mut all_certs = vec![cert];
    for cert in cabundle {
        let cert = (match cert {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::ParseFailed("cert decode".into())),
        })?;
        let cert = X509::from_der(&cert)
            .map_err(|e| AttestationError::ParseFailed(format!("der: {e}")))?;
        all_certs.push(cert);
    }
    Ok(all_certs)
}

fn verify_cert_chain(
    cert: X509,
    cabundle: Vec<Value>,
    root_cert_pem: Vec<u8>,
) -> Result<(), AttestationError> {
    let certs = get_all_certs(cert, cabundle)?;

    for i in 0..(certs.len() - 1) {
        let pubkey = certs[i + 1]
            .public_key()
            .map_err(|e| AttestationError::ParseFailed(format!("pubkey: {e}")))?;
        if !certs[i]
            .verify(&pubkey)
            .map_err(|e| AttestationError::ParseFailed(format!("signature: {e}")))?
        {
            return Err(AttestationError::VerifyFailed("signature".into()));
        }
        if certs[i + 1].issued(&certs[i]) != X509VerifyResult::OK {
            return Err(AttestationError::VerifyFailed("issuer or subject".into()));
        }
        let current_time =
            Asn1Time::days_from_now(0).map_err(|e| AttestationError::ParseFailed(e.to_string()))?;
        if certs[i].not_after() < current_time || certs[i].not_before() > current_time {
            return Err(AttestationError::VerifyFailed("timestamp".into()));
        }
    }

    let root_cert = X509::from_pem(&root_cert_pem)
        .map_err(|e| AttestationError::ParseFailed(format!("pem: {e}")))?;
    if &root_cert
        != certs
            .last()
            .ok_or(AttestationError::ParseFailed("root".into()))?
    {
        return Err(AttestationError::VerifyFailed("root".into()));
    }
    Ok(())
}

fn parse_attestation_doc(
    attestation_doc: &[u8],
) -> Result<(CoseSign1, BTreeMap<Value, Value>), AttestationError> {
    let cosesign1 = CoseSign1::from_bytes(&attestation_doc)
        .map_err(|e| AttestationError::ParseFailed(format!("cose: {e}")))?;
    let payload = cosesign1
        .get_payload::<Openssl>(None)
        .map_err(|e| AttestationError::ParseFailed(format!("cose payload: {e}")))?;
    let cbor = serde_cbor::from_slice::<Value>(&payload)
        .map_err(|e| AttestationError::ParseFailed(format!("cbor: {e}")))?;
    let attestation_doc = value::from_value::<BTreeMap<Value, Value>>(cbor)
        .map_err(|e| AttestationError::ParseFailed(format!("doc: {e}")))?;

    Ok((cosesign1, attestation_doc))
}

fn parse_pcrs(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<Vec<String>, AttestationError> {
    let pcrs_arr = attestation_doc
        .remove(&"pcrs".to_owned().into())
        .ok_or(AttestationError::ParseFailed("pcrs not found".into()))?;
    let mut pcrs_arr = value::from_value::<BTreeMap<Value, Value>>(pcrs_arr)
        .map_err(|e| AttestationError::ParseFailed(format!("pcrs: {e}")))?;

    let mut result = vec![];
    for i in 0u8..3u8 {
        let pcr = pcrs_arr
            .remove(&i.into())
            .ok_or(AttestationError::ParseFailed(format!("pcr{i} not found")))?;
        let pcr = (match pcr {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::ParseFailed(format!(
                "pcr{i} decode failure"
            ))),
        })?;
        result.push(hex::encode(pcr));
    }

    Ok(result)
}

fn verify_signature_and_cert_chain(
    attestation_doc: &mut BTreeMap<Value, Value>,
    cosesign1: &CoseSign1,
) -> Result<(), AttestationError> {
    // verify attestation doc signature
    let enclave_certificate = attestation_doc
        .remove(&"certificate".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "certificate key not found".to_owned(),
        ))?;
    let enclave_certificate = (match enclave_certificate {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "enclave certificate decode failure".to_owned(),
        )),
    })?;
    let enclave_certificate = X509::from_der(&enclave_certificate)
        .map_err(|e| AttestationError::ParseFailed(format!("der: {e}")))?;
    let pub_key = enclave_certificate
        .public_key()
        .map_err(|e| AttestationError::ParseFailed(format!("pubkey: {e}")))?;
    let verify_result = cosesign1
        .verify_signature::<Openssl>(&pub_key)
        .map_err(|e| AttestationError::ParseFailed(format!("signature: {e}")))?;

    if !verify_result {
        return Err(AttestationError::VerifyFailed("signature".into()));
    }

    // verify certificate chain
    let cabundle = attestation_doc
        .remove(&"cabundle".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "cabundle key not found in attestation doc".to_owned(),
        ))?;
    let mut cabundle = (match cabundle {
        Value::Array(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "cabundle decode failure".to_owned(),
        )),
    })?;
    cabundle.reverse();

    let root_cert_pem = include_bytes!("./aws.cert").to_vec();
    verify_cert_chain(enclave_certificate, cabundle, root_cert_pem)?;

    Ok(())
}

pub fn verify(
    attestation_doc_cbor: Vec<u8>,
    pcrs: Vec<String>,
    min_cpus: usize,
    min_mem: usize,
    max_age: usize,
) -> Result<[u8; 32], AttestationError> {
    // verify attestation and decode fields
    let decoded_data = verify_and_decode_attestation(attestation_doc_cbor)?;

    for i in 0..3 {
        if decoded_data.pcrs[i] != pcrs[i] {
            return Err(AttestationError::VerifyFailed(format!("pcr{i}")));
        }
    }

    if decoded_data.total_cpus < min_cpus {
        return Err(AttestationError::VerifyFailed("minimum cpus".into()));
    }
    if decoded_data.total_memory < min_mem {
        return Err(AttestationError::VerifyFailed("minimum memory".into()));
    }

    // verify age
    let now = Utc::now().timestamp_millis();
    if (now as usize) - max_age > decoded_data.timestamp {
        return Err(AttestationError::VerifyFailed("too old".into()));
    }

    Ok(decoded_data.ed25519_public)
}

pub async fn get_attestation_doc(endpoint: Uri) -> Result<Vec<u8>, AttestationError> {
    let client = Client::new();
    let res = client.get(endpoint).await?;
    Ok(hyper::body::to_bytes(res).await?.to_vec())
}

pub fn decode_attestation(
    attestation_doc: Vec<u8>,
) -> Result<AttestationDecoded, AttestationError> {
    let mut result = AttestationDecoded {
        pcrs: Vec::new(),
        total_cpus: 0,
        total_memory: 0,
        timestamp: 0,
        ed25519_public: [0; 32],
    };

    // parse attestation doc
    let (_, mut attestation_doc) = parse_attestation_doc(&attestation_doc)?;

    // parse pcrs
    result.pcrs = parse_pcrs(&mut attestation_doc)?;

    // parse cpu and memory
    let user_data = attestation_doc
        .remove(&"user_data".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "user data not found in attestation doc".to_owned(),
        ))?;
    let user_data = (match user_data {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "user data decode failure".into(),
        )),
    })?;
    let size = serde_json::from_slice::<EnclaveConfig>(user_data.as_slice())
        .map_err(|e| AttestationError::ParseFailed(format!("enclave config: {e}")))?;
    result.total_cpus = size.total_cpus;
    result.total_memory = size.total_memory;

    // parse timestamp
    let timestamp = attestation_doc
        .remove(&"timestamp".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "timestamp not found in attestation doc".to_owned(),
        ))?;
    let timestamp = (match timestamp {
        Value::Integer(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "timestamp decode failure".to_owned(),
        )),
    })?;
    result.timestamp = timestamp
        .try_into()
        .map_err(|e| AttestationError::ParseFailed(format!("timestamp: {e}")))?;

    // parse the enclave key
    let public_key = attestation_doc
        .remove(&"public_key".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "public key not found in attestation doc".to_owned(),
        ))?;
    let public_key = (match public_key {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "public key decode failure".to_owned(),
        )),
    })?;

    result.ed25519_public = public_key
        .as_slice()
        .try_into()
        .map_err(|e| AttestationError::ParseFailed(format!("pubkey: {e}")))?;

    Ok(result)
}

pub fn verify_and_decode_attestation(
    attestation_doc: Vec<u8>,
) -> Result<AttestationDecoded, AttestationError> {
    let mut result = AttestationDecoded {
        pcrs: Vec::new(),
        total_cpus: 0,
        total_memory: 0,
        timestamp: 0,
        ed25519_public: [0u8; 32],
    };

    // parse attestation doc
    let (cosesign1, mut attestation_doc) = parse_attestation_doc(&attestation_doc)?;

    // parse pcrs
    result.pcrs = parse_pcrs(&mut attestation_doc)?;

    // verify attestation doc signature
    let enclave_certificate = attestation_doc
        .remove(&"certificate".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "certificate key not found".to_owned(),
        ))?;
    let enclave_certificate = (match enclave_certificate {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "enclave certificate decode failure".to_owned(),
        )),
    })?;
    let enclave_certificate = X509::from_der(&enclave_certificate)
        .map_err(|e| AttestationError::ParseFailed(format!("der: {e}")))?;
    let pub_key = enclave_certificate
        .public_key()
        .map_err(|e| AttestationError::ParseFailed(format!("pubkey: {e}")))?;
    let verify_result = cosesign1
        .verify_signature::<Openssl>(&pub_key)
        .map_err(|e| AttestationError::ParseFailed(format!("signature: {e}")))?;

    if !verify_result {
        return Err(AttestationError::VerifyFailed("signature".into()));
    }

    // verify certificate chain
    let cabundle = attestation_doc
        .remove(&"cabundle".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "cabundle key not found in attestation doc".to_owned(),
        ))?;
    let mut cabundle = (match cabundle {
        Value::Array(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "cabundle decode failure".to_owned(),
        )),
    })?;
    cabundle.reverse();

    let root_cert_pem = include_bytes!("./aws.cert").to_vec();
    verify_cert_chain(enclave_certificate, cabundle, root_cert_pem)?;

    // parse cpu and memory
    let user_data = attestation_doc
        .remove(&"user_data".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "user data not found in attestation doc".to_owned(),
        ))?;
    let user_data = (match user_data {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "user data decode failure".into(),
        )),
    })?;
    let size = serde_json::from_slice::<EnclaveConfig>(user_data.as_slice())
        .map_err(|e| AttestationError::ParseFailed(format!("enclave config: {e}")))?;
    result.total_cpus = size.total_cpus;
    result.total_memory = size.total_memory;

    // parse timestamp
    let timestamp = attestation_doc
        .remove(&"timestamp".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "timestamp not found in attestation doc".to_owned(),
        ))?;
    let timestamp = (match timestamp {
        Value::Integer(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "timestamp decode failure".to_owned(),
        )),
    })?;
    result.timestamp = timestamp
        .try_into()
        .map_err(|e| AttestationError::ParseFailed(format!("timestamp: {e}")))?;

    // return the enclave key
    let public_key = attestation_doc
        .remove(&"public_key".to_owned().into())
        .ok_or(AttestationError::ParseFailed(
            "public key not found in attestation doc".to_owned(),
        ))?;
    let public_key = (match public_key {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::ParseFailed(
            "public key decode failure".to_owned(),
        )),
    })?;

    result.ed25519_public = public_key
        .as_slice()
        .try_into()
        .map_err(|e| AttestationError::ParseFailed(format!("pubkey: {e}")))?;

    Ok(result)
}
