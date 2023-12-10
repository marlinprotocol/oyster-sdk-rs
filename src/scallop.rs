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

use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

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

#[derive(PartialEq)]
enum ReadMode {
    Length,
    Body,
    Read,
}

pub struct ScallopStream<Stream: AsyncWrite + AsyncRead + Unpin> {
    noise: TransportState,
    stream: Stream,

    // read buffer
    buf: Box<[u8]>,
    pending: usize,
    mode: ReadMode,
    read_end: usize,
    read_start: usize,
}

#[allow(non_snake_case)]
pub async fn new_client_async_Noise_XX_25519_ChaChaPoly_BLAKE2s<
    Base: AsyncWrite + AsyncRead + Unpin,
>(
    mut stream: Base,
    secret: &[u8; 32],
) -> Result<ScallopStream<Base>, ScallopError> {
    let mut buf = [0u8; 1024];
    let mut noise_buf = [0u8; 1024];

    let prologue = b"NoiseSocketInit1\x00\x00";

    let mut noise = Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_initiator()
    .map_err(ScallopError::InitFailed)?;

    //---- -> e start ----//

    // first two bytes are already zero, skip writing negotiation payload

    // handshake message
    let size = noise.write_message(&[], &mut buf[4..])?;

    // handshake length
    buf[2..4].copy_from_slice(&(size as u16).to_be_bytes());

    // send to the server
    stream.write_all(&buf[0..4 + size]).await?;

    //---- -> e end ----//

    //---- <- e, ee, s, es start ----//

    // read negotiation length
    let len = stream.read_u16().await?;

    // length should be zero
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero negotiation length".into(),
        ));
    }

    // read noise message length
    let len = stream.read_u16().await?;

    // read handshake message
    stream.read_exact(&mut buf[0..len as usize]).await?;

    // handle handshake message
    let len = noise.read_message(&buf[0..len as usize], &mut noise_buf)?;

    // handshake payload should be empty
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero first handshake payload".into(),
        ));
    }

    //---- <- e, ee, s, es end ----//

    //---- -> s, se start ----//

    // negotiation length
    buf[0..2].copy_from_slice(&0u16.to_be_bytes());

    // handshake message
    let size = noise.write_message(&[], &mut buf[4..])?;

    // handshake length
    buf[2..4].copy_from_slice(&(size as u16).to_be_bytes());

    // send to the server
    stream.write_all(&buf[0..4 + size]).await?;

    //---- -> s, se end ----//

    // handshake is done, switch to transport mode
    let noise = noise.into_transport_mode()?;

    Ok(ScallopStream {
        noise,
        stream,
        buf: vec![0u8; 2].into_boxed_slice(),
        pending: 2,
        mode: ReadMode::Length,
        read_start: 0,
        read_end: 0,
    })
}

#[allow(non_snake_case)]
pub async fn new_server_async_Noise_XX_25519_ChaChaPoly_BLAKE2s<
    Base: AsyncWrite + AsyncRead + Unpin,
>(
    mut stream: Base,
    secret: &[u8; 32],
) -> Result<ScallopStream<Base>, ScallopError> {
    let mut buf = [0u8; 1024];
    let mut noise_buf = [0u8; 1024];

    let prologue = b"NoiseSocketInit1\x00\x00";

    let mut noise = Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(ScallopError::InitFailed)?,
    )
    .local_private_key(secret)
    .prologue(prologue)
    .build_responder()
    .map_err(ScallopError::InitFailed)?;

    //---- -> e start ----//

    // read negotiation length
    let len = stream.read_u16().await?;

    // length should be zero
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero negotiation length".into(),
        ));
    }

    // read noise message length
    let len = stream.read_u16().await?;

    // read handshake message
    stream.read_exact(&mut buf[0..len as usize]).await?;

    // handle handshake message
    let len = noise.read_message(&buf[0..len as usize], &mut noise_buf)?;

    // handshake payload should be empty
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero first handshake payload".into(),
        ));
    }

    //---- -> e end ----//

    //---- <- e, ee, s, es start ----//

    // negotiation length
    buf[0..2].copy_from_slice(&0u16.to_be_bytes());

    // handshake message
    let size = noise.write_message(&[], &mut buf[4..])?;

    // handshake length
    buf[2..4].copy_from_slice(&(size as u16).to_be_bytes());

    // send to the client
    stream.write_all(&buf[0..4 + size]).await?;

    //---- <- e, ee, s, es end ----//

    //---- -> s, se start ----//

    // read negotiation length
    let len = stream.read_u16().await?;

    // length should be zero
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero negotiation length".into(),
        ));
    }

    // read noise message length
    let len = stream.read_u16().await?;

    // read handshake message
    stream.read_exact(&mut buf[0..len as usize]).await?;

    // handle handshake message
    let len = noise.read_message(&buf[0..len as usize], &mut noise_buf)?;

    // handshake payload should be empty
    if len != 0 {
        return Err(ScallopError::ProtocolError(
            "non zero first handshake payload".into(),
        ));
    }

    //---- -> s, se end ----//

    // handshake is done, switch to transport mode
    let noise = noise.into_transport_mode()?;

    Ok(ScallopStream {
        noise,
        stream,
        buf: vec![0u8; 2].into_boxed_slice(),
        pending: 2,
        mode: ReadMode::Length,
        read_start: 0,
        read_end: 0,
    })
}

impl<Base: AsyncWrite + AsyncRead + Unpin> AsyncRead for ScallopStream<Base> {
    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let stream = self.get_mut();
        loop {
            while stream.pending != 0 {
                let base = std::pin::pin!(&mut stream.stream);

                // do not have enough data, try to read more
                let len = stream.buf.len();
                let mut buf = ReadBuf::new(&mut stream.buf[(len - stream.pending)..]);
                std::task::ready!(base.poll_read(cx, &mut buf))?;

                // check eof
                if buf.filled().len() == 0 {
                    return std::task::Poll::Ready(Ok(()));
                }
                stream.pending -= buf.filled().len();
            }

            // pending should always be 0 after this point

            if stream.mode == ReadMode::Length {
                // we have read the length

                // parse length
                let record_length = u16::from_be_bytes(stream.buf[0..2].try_into().unwrap());

                // set up to read record
                stream.pending = record_length.into();
                stream.mode = ReadMode::Body;
                stream.buf = vec![0u8; stream.pending].into_boxed_slice();
            } else if stream.mode == ReadMode::Body {
                // we have the data

                // process as noise message
                let len = stream
                    .noise
                    .read_message(&stream.buf.clone(), &mut stream.buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                // set up to send body upstream
                stream.read_start = 0;
                stream.read_end = len;
                stream.mode = ReadMode::Read;
            } else {
                if buf.remaining() < stream.read_end - stream.read_start {
                    // can transmit only partial
                    let read_start = stream.read_start;
                    stream.read_start += buf.remaining();
                    let read_end = read_start + buf.remaining();
                    buf.put_slice(&stream.buf[read_start..read_end]);
                } else {
                    // can transmit full
                    buf.put_slice(&stream.buf[stream.read_start..stream.read_end]);

                    stream.buf = vec![0u8; 2].into_boxed_slice();
                    stream.pending = 2;
                    stream.mode = ReadMode::Length;
                }
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}
