// Scallop protocol
//
// Broad goals:
// - Transport layer security (the concept not the protocol)
// - Enclave native protocol (no Web PKI)
// - Modern cryptography
//
// Handshake shape and security levels in the user stories are modelled on the Noise protocol specification.
//
// User story 1 - HTTP query against known server:
//
// Server is running inside an enclave.
// Client has authenticated the attestation of the enclave and has the static key.
//
// Client wants to create a secure channel with the server to make a HTTP query.
//
// Client to server requires a security level of 0/5.
// Server to client requires a security level of 2/1.
// NK is the minimum viable handshake.
// With 1RTT client delay and 0.5RTT server delay.
//
// Bonuses:
// - Authentication refresh on expiry
//   - Client can request a new attestation in the first message
//   - Server can send the payload in the second message
//
// User story 2 - HTTP query against unknown server:
//
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
//
// Client wants to create a secure channel with the server to make a HTTP query.
//
// Client to server requires a security level of 0/5.
// Server to client requires a security level of 2/1.
// NX is the minimum viable handshake.
// With 1RTT client delay and 0.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//
// User story 3 - webhook trigger from a known client to a known server:
//
// Client is running inside an enclave.
// Client has the static key of the server.
// Server has previously authenticated the attestation of the client and has the static key.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// KK is the minimum viable handshake.
// With 1 RTT client delay and 0.5RTT server delay.
//
// User story 4 - webhook trigger from a known client to an unknown server:
//
// Client is running inside an enclave.
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
// Server has previously authenticated the attestation of the client and has the static key.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// KX is the minimum viable handshake.
// With 1 RTT client delay and 0.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//
// User story 5 - webhook trigger from an unknown client to a known server:
//
// Client is running inside an enclave.
// Client has the static key of the server.
// Server knows the expected PCRs of the client.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// XK is the minimum viable handshake.
// With 1 RTT client delay and 1.5RTT server delay.
// With additional handshake payloads
//   - Server requests a new attestation in the second message
//   - Client sends the attestation in the third message
//
// User story 6 - webhook trigger from an unknown client to an unknown server:
//
// Client is running inside an enclave.
// Server is running inside an enclave.
// Client knows the expected PCRs of the server.
// Server knows the expected PCRs of the client.
//
// Client wants to create a secure channel with the server and trigger a webhook.
//
// Client to server requires a security level of 2/5.
// Server to client requires a security level of 2/5.
// XX is the minimum viable handshake.
// With 1 RTT client delay and 1.5RTT server delay.
// With additional handshake payloads
//   - Client requests a new attestation in the first message
//   - Server sends the attestation in the second message
//   - Server requests a new attestation in the second message
//   - Client sends the attestation in the third message
//
// User story considerations:
// - various handshake shapes
// - various security levels
// - handshake latency
// - handshake efficiency
//   - not having to send attestations unless requested by the other party
//   - (questionable?) not having to send static keys unless requested by the other party
//
// General considerations:
// - Different cipher suites
// - Protocol evolution
//
// Conclusions:
// Pick XX as the Noise Protocol
// - Most flexible and covers wide variety of use cases
// - At the cost of a higher server delay
// - At the cost of a lower security level for handshake messages themselves
// - At the cost of handshake messages being larger
// - But allows the significantly larger attestations to be optional in both directions
//
// Pick NoiseSocket as the negotiation protocol
//
// TODOs:
// - (desirable?) 0RTT

use snow::Builder;

#[derive(thiserror::Error, Debug)]
pub enum ScallopError {
    #[error("failed to init builder")]
    InitFailed(#[source] snow::Error),
    #[error("transport error")]
    TransportError(#[from] tokio::io::Error),
    #[error("noise error")]
    NoiseError(#[from] snow::Error),
    #[error("protocol error")]
    ProtocolError(String),
}

#[allow(non_snake_case)]
async fn new_client_async_Noise_XX_25519_ChaChaPoly_BLAKE2s(
    secret: &[u8],
) -> Result<(), ScallopError> {
    let prologue = b"NoiseSocketInit1\x00\x00";

    let noise = Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_initiator()
    .map_err(ScallopError::InitFailed)?;

    Ok(())
}

#[allow(non_snake_case)]
async fn new_server_async_Noise_XX_25519_ChaChaPoly_BLAKE2s(
    secret: &[u8],
) -> Result<(), ScallopError> {
    let prologue = b"NoiseSocketInit1\x00\x00";

    let noise = Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_responder()
    .map_err(ScallopError::InitFailed)?;

    Ok(())
}
