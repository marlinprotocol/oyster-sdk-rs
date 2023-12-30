use libsodium_sys::{
    crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_auth, crypto_auth_verify, crypto_generichash_blake2b_final,
    crypto_generichash_blake2b_init, crypto_generichash_blake2b_state,
    crypto_generichash_blake2b_update, crypto_kdf_derive_from_key, crypto_scalarmult,
    crypto_sign_detached, crypto_sign_verify_detached, randombytes_buf,
};
use std::ffi::c_int;
use std::io::Write;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(thiserror::Error, Debug)]
pub enum MolluskError {
    #[error("failed to init libsodium")]
    InitFailed,
    #[error("failed to decrypt a message, might indicate forgery")]
    DecryptFailed,
    #[error("failed to authenticate, might indicate impersonation")]
    AuthFailed,
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("mismatched version, expected {0}, found {1}")]
    VersionMismatch(u8, u8),
    #[error("unexpected record type, expected {0}, found {1}")]
    RecordTypeMismatch(u8, u8),
    #[error("failed to parse record")]
    ParseError,
}

trait Errorable {
    fn error(&self, err: impl Into<MolluskError>) -> Result<(), MolluskError>;
}

impl Errorable for c_int {
    fn error(&self, err: impl Into<MolluskError>) -> Result<(), MolluskError> {
        if self.is_negative() {
            return Err(err.into());
        }

        Ok(())
    }
}

#[derive(Clone)]
struct Hasher {
    state: crypto_generichash_blake2b_state,
}

impl Hasher {
    fn new() -> Hasher {
        Hasher {
            state: crypto_generichash_blake2b_state { opaque: [0; 384] },
        }
    }

    fn init(&mut self) -> &mut Self {
        // cannot fail
        unsafe { crypto_generichash_blake2b_init(&mut self.state, std::ptr::null(), 0, 32) };

        self
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        unsafe {
            // cannot fail
            crypto_generichash_blake2b_update(&mut self.state, data.as_ptr(), data.len() as u64)
        };

        self
    }

    fn finalize(&mut self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        // cannot fail
        unsafe { crypto_generichash_blake2b_final(&mut self.state, hash.as_mut_ptr(), 32) };

        hash
    }
}

fn sodium_init() -> Result<(), MolluskError> {
    unsafe { libsodium_sys::sodium_init() }.error(MolluskError::InitFailed)
}

fn crypto_kx_keypair() -> ([u8; 32], [u8; 32]) {
    let mut seckey = [0u8; 32];
    let mut pubkey = [0u8; 32];
    // cannot fail
    unsafe { libsodium_sys::crypto_kx_keypair(pubkey.as_mut_ptr(), seckey.as_mut_ptr()) };

    (seckey, pubkey)
}

// Record format:
// 1 byte version
// 1 byte record type
// 2 byte length
// N byte record data
#[repr(u8)]
enum RecordType {
    // 32 byte client random
    // 32 byte key share
    // 2 byte extensions length
    // N x (2 byte type + 2 byte length + N byte data) extensions
    ClientHello = 0,

    // 32 byte server random
    // 32 byte key share
    // 2 byte extensions length
    // N x (2 byte type + 2 byte length + N byte data) extensions
    ServerHello = 1,

    // 24 byte nonce
    // encrypted using handshake key
    // 64 byte signature
    // 16 byte auth tag
    Auth = 2,

    // 24 byte nonce
    // encrypted using handshake key
    // 32 byte MAC
    // 16 byte auth tag
    HandshakeFinish = 3,

    // 24 byte nonce
    // encrypted using handshake key
    // 2 byte length
    // N byte data
    // 16 byte auth tag
    Data = 4,
}

#[derive(Debug)]
pub struct MolluskStream<Base: AsyncWrite + AsyncRead + Unpin> {
    // base stream for the connection
    base: Base,
    // rx key
    rx_key: [u8; 32],
    // tx key
    tx_key: [u8; 32],
    // read buffer
    buf: Box<[u8]>,
    pending: usize,
    mode: bool,
    pending_read: usize,
    // write buffer
    wbuf: Box<[u8]>,
    pending_write: usize,
}

impl<Base: AsyncWrite + AsyncRead + Unpin> MolluskStream<Base> {
    // client mode
    pub async fn new_client(
        base: Base,
        server_pubkey: [u8; 32],
    ) -> Result<MolluskStream<Base>, MolluskError> {
        let mut stream = MolluskStream {
            base,
            rx_key: [0; 32],
            tx_key: [0; 32],
            buf: vec![0u8; 4].into_boxed_slice(),
            pending: 4,
            mode: false,
            pending_read: 0,
            wbuf: Box::new([0u8; 0]),
            pending_write: 0,
        };

        // init libsodium
        sodium_init()?;

        // generate local ephemeral key pair
        let (client_seckey_eph, client_pubkey_eph) = crypto_kx_keypair();

        let mut client_random = [0u8; 32];
        unsafe {
            randombytes_buf(client_random.as_mut_ptr().cast(), 32);
        }

        let mut session_hasher = Hasher::new();
        session_hasher.init();

        {
            // first message of handshake - ClientHello

            let mut msg = [0u8; 70];
            msg[0] = 0;
            msg[1] = RecordType::ClientHello as u8;
            (&mut msg[2..4]).write_all(&66u16.to_le_bytes())?;
            (&mut msg[4..36]).write_all(&client_random)?;
            (&mut msg[36..68]).write_all(&client_pubkey_eph)?;
            (&mut msg[68..70]).write_all(&0u16.to_le_bytes())?;

            stream.base.write_all(&msg).await?;
            stream.base.flush().await?;

            session_hasher.update(&msg);
        }

        let server_pubkey_eph: [u8; 32];
        let mut client_handshake_key = [0u8; 32];
        let mut server_handshake_key = [0u8; 32];
        let handshake_secret: [u8; 32];

        {
            // second message of handshake - ServerHello

            // version check
            let version = stream.base.read_u8().await?;
            if version != 0 {
                return Err(MolluskError::VersionMismatch(0, version));
            }

            // record type check
            let record_type = stream.base.read_u8().await?;
            if record_type != RecordType::ServerHello as u8 {
                return Err(MolluskError::RecordTypeMismatch(
                    RecordType::ServerHello as u8,
                    record_type,
                ));
            }

            // length check
            let record_length = stream.base.read_u16_le().await?;
            if record_length < 66 {
                return Err(MolluskError::ParseError);
            }

            // read
            let mut msg = vec![0u8; record_length as usize].into_boxed_slice();
            stream.base.read_exact(&mut msg).await?;

            server_pubkey_eph = msg[32..64]
                .try_into()
                .map_err(|_| MolluskError::ParseError)?;

            session_hasher
                .update(&[version])
                .update(&[record_type])
                .update(&record_length.to_le_bytes())
                .update(&msg);

            let mut shared_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_scalarmult(
                    shared_key.as_mut_ptr(),
                    client_seckey_eph.as_ptr(),
                    server_pubkey_eph.as_ptr(),
                )
            };

            handshake_secret = Hasher::new()
                .init()
                .update(&shared_key)
                .update(&client_pubkey_eph)
                .update(&server_pubkey_eph)
                .update(&session_hasher.clone().finalize())
                .finalize();

            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    client_handshake_key.as_mut_ptr(),
                    32,
                    1,
                    "clienthk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
                // cannot fail
                crypto_kdf_derive_from_key(
                    server_handshake_key.as_mut_ptr(),
                    32,
                    2,
                    "serverhk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
            }
        }

        {
            // expect Auth to verify identity

            // version check
            let version = stream.base.read_u8().await?;
            if version != 0 {
                return Err(MolluskError::VersionMismatch(0, version));
            }

            // record type check
            let record_type = stream.base.read_u8().await?;
            if record_type != RecordType::Auth as u8 {
                return Err(MolluskError::RecordTypeMismatch(
                    RecordType::Auth as u8,
                    record_type,
                ));
            }

            // length check
            let record_length = stream.base.read_u16_le().await?;
            if record_length != 104 {
                return Err(MolluskError::ParseError);
            }

            // read
            let mut msg = vec![0u8; 4 + record_length as usize].into_boxed_slice();
            msg[0] = version;
            msg[1] = record_type;
            (&mut msg[2..4]).write_all(&record_length.to_le_bytes())?;
            stream.base.read_exact(&mut msg[4..]).await?;

            unsafe {
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    80,
                    msg.as_ptr(),
                    28,
                    msg.as_ptr().add(4),
                    server_handshake_key.as_ptr(),
                )
            }
            .error(MolluskError::DecryptFailed)?;

            unsafe {
                crypto_sign_verify_detached(
                    msg.as_ptr().add(28),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    server_pubkey.as_ptr(),
                )
            }
            .error(MolluskError::AuthFailed)?;

            session_hasher.update(&msg[..92]);
        }

        {
            // expect HandshakeFinish

            // version check
            let version = stream.base.read_u8().await?;
            if version != 0 {
                return Err(MolluskError::VersionMismatch(0, version));
            }

            // record type check
            let record_type = stream.base.read_u8().await?;
            if record_type != RecordType::HandshakeFinish as u8 {
                return Err(MolluskError::RecordTypeMismatch(
                    RecordType::HandshakeFinish as u8,
                    record_type,
                ));
            }

            // length check
            let record_length = stream.base.read_u16_le().await?;
            if record_length != 72 {
                return Err(MolluskError::ParseError);
            }

            // read
            let mut msg = vec![0u8; 4 + record_length as usize].into_boxed_slice();
            msg[0] = version;
            msg[1] = record_type;
            (&mut msg[2..4]).write_all(&record_length.to_le_bytes())?;
            stream.base.read_exact(&mut msg[4..]).await?;

            unsafe {
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    48,
                    msg.as_ptr(),
                    28,
                    msg.as_ptr().add(4),
                    server_handshake_key.as_ptr(),
                )
            }
            .error(MolluskError::DecryptFailed)?;

            let mut server_finished_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    server_finished_key.as_mut_ptr(),
                    32,
                    1,
                    "finished".as_ptr().cast(),
                    server_handshake_key.as_ptr(),
                );
            }

            unsafe {
                crypto_auth_verify(
                    msg.as_ptr().add(28),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    server_finished_key.as_ptr(),
                )
            }
            .error(MolluskError::AuthFailed)?;

            session_hasher.update(&msg[..60]);
        }

        {
            // send HandshakeFinish to finish handshake on the client

            let mut client_finished_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    client_finished_key.as_mut_ptr(),
                    32,
                    1,
                    "finished".as_ptr().cast(),
                    client_handshake_key.as_ptr(),
                );
            }

            let mut msg = [0u8; 76];
            msg[0] = 0;
            msg[1] = RecordType::HandshakeFinish as u8;
            (&mut msg[2..4]).write_all(&72u16.to_le_bytes())?;
            unsafe {
                // cannot fail
                randombytes_buf(msg.as_mut_ptr().add(4).cast(), 24);
                // cannot fail
                crypto_auth(
                    msg.as_mut_ptr().add(28),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    client_finished_key.as_ptr(),
                );
            };

            session_hasher.update(&msg[..60]);

            unsafe {
                // cannot fail
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    32,
                    msg.as_ptr(),
                    28,
                    std::ptr::null(),
                    msg.as_ptr().add(4),
                    client_handshake_key.as_ptr(),
                );
            };

            stream.base.write_all(&msg).await?;
            stream.base.flush().await?;
        }

        {
            // calculate rx/tx keys

            let mut derived_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    derived_key.as_mut_ptr(),
                    32,
                    1,
                    "derivedk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
            }

            let application_secret = Hasher::new()
                .init()
                .update(&derived_key)
                .update(&session_hasher.finalize())
                .finalize();

            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    stream.tx_key.as_mut_ptr(),
                    32,
                    1,
                    "clientap".as_ptr().cast(),
                    application_secret.as_ptr(),
                );
                // cannot fail
                crypto_kdf_derive_from_key(
                    stream.rx_key.as_mut_ptr(),
                    32,
                    2,
                    "serverap".as_ptr().cast(),
                    application_secret.as_ptr(),
                );
            }
        }

        // FIN

        Ok(stream)
    }

    // server mode
    pub async fn new_server(
        base: Base,
        server_seckey: [u8; 64],
    ) -> Result<MolluskStream<Base>, MolluskError> {
        let mut stream = MolluskStream {
            base,
            rx_key: [0; 32],
            tx_key: [0; 32],
            buf: vec![0u8; 4].into_boxed_slice(),
            pending: 4,
            mode: false,
            pending_read: 0,
            wbuf: Box::new([0u8; 0]),
            pending_write: 0,
        };

        // init libsodium
        sodium_init()?;

        // generate local ephemeral key pair
        let (server_seckey_eph, server_pubkey_eph) = crypto_kx_keypair();

        let mut session_hasher = Hasher::new();
        session_hasher.init();

        let client_pubkey_eph: [u8; 32];

        {
            // first message of handshake - ClientHello

            // version check
            let version = stream.base.read_u8().await?;
            if version != 0 {
                return Err(MolluskError::VersionMismatch(0, version));
            }

            // record type check
            let record_type = stream.base.read_u8().await?;
            if record_type != RecordType::ClientHello as u8 {
                return Err(MolluskError::RecordTypeMismatch(
                    RecordType::ClientHello as u8,
                    record_type,
                ));
            }

            // length check
            let record_length = stream.base.read_u16_le().await?;
            if record_length < 66 {
                return Err(MolluskError::ParseError);
            }

            // read
            let mut msg = vec![0u8; record_length as usize].into_boxed_slice();
            stream.base.read_exact(&mut msg).await?;

            client_pubkey_eph = msg[32..64]
                .try_into()
                .map_err(|_| MolluskError::ParseError)?;

            session_hasher
                .update(&[version])
                .update(&[record_type])
                .update(&record_length.to_le_bytes())
                .update(&msg);
        }

        let mut server_random = [0u8; 32];
        unsafe {
            randombytes_buf(server_random.as_mut_ptr().cast(), 32);
        }

        let mut client_handshake_key = [0u8; 32];
        let mut server_handshake_key = [0u8; 32];
        let handshake_secret: [u8; 32];

        {
            // second message of handshake - ServerHello

            let mut msg = [0u8; 70];
            msg[0] = 0;
            msg[1] = RecordType::ServerHello as u8;
            (&mut msg[2..4]).write_all(&66u16.to_le_bytes())?;
            unsafe {
                randombytes_buf(msg.as_mut_ptr().add(4).cast(), 32);
            }
            (&mut msg[36..68]).write_all(&server_pubkey_eph)?;
            (&mut msg[68..70]).write_all(&0u16.to_le_bytes())?;

            stream.base.write_all(&msg).await?;
            stream.base.flush().await?;

            session_hasher.update(&msg);

            let mut shared_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_scalarmult(
                    shared_key.as_mut_ptr(),
                    server_seckey_eph.as_ptr(),
                    client_pubkey_eph.as_ptr(),
                );
            }

            handshake_secret = Hasher::new()
                .init()
                .update(&shared_key)
                .update(&client_pubkey_eph)
                .update(&server_pubkey_eph)
                .update(&session_hasher.clone().finalize())
                .finalize();

            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    client_handshake_key.as_mut_ptr(),
                    32,
                    1,
                    "clienthk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
                // cannot fail
                crypto_kdf_derive_from_key(
                    server_handshake_key.as_mut_ptr(),
                    32,
                    2,
                    "serverhk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
            }
        }

        {
            // send Auth to verify identity

            let mut msg = [0u8; 108];
            msg[0] = 0;
            msg[1] = RecordType::Auth as u8;
            (&mut msg[2..4]).write_all(&104u16.to_le_bytes())?;
            unsafe {
                // cannot fail
                randombytes_buf(msg.as_mut_ptr().add(4).cast(), 24);
                // cannot fail
                crypto_sign_detached(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    server_seckey.as_ptr(),
                );
            };

            session_hasher.update(&msg[..92]);

            unsafe {
                // cannot fail
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    64,
                    msg.as_ptr(),
                    28,
                    std::ptr::null(),
                    msg.as_ptr().add(4),
                    server_handshake_key.as_ptr(),
                );
            };

            stream.base.write_all(&msg).await?;
            stream.base.flush().await?;
        }

        {
            // send HandshakeFinish to finish handshake on the server

            let mut server_finished_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    server_finished_key.as_mut_ptr(),
                    32,
                    1,
                    "finished".as_ptr().cast(),
                    server_handshake_key.as_ptr(),
                );
            }

            let mut msg = [0u8; 76];
            msg[0] = 0;
            msg[1] = RecordType::HandshakeFinish as u8;
            (&mut msg[2..4]).write_all(&72u16.to_le_bytes())?;
            unsafe {
                // cannot fail
                randombytes_buf(msg.as_mut_ptr().add(4).cast(), 24);
                // cannot fail
                crypto_auth(
                    msg.as_mut_ptr().add(28),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    server_finished_key.as_ptr(),
                );
            };

            session_hasher.update(&msg[..60]);

            unsafe {
                // cannot fail
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    32,
                    msg.as_ptr(),
                    28,
                    std::ptr::null(),
                    msg.as_ptr().add(4),
                    server_handshake_key.as_ptr(),
                );
            };

            stream.base.write_all(&msg).await?;
            stream.base.flush().await?;
        }

        {
            // expect HandshakeFinish

            // version check
            let version = stream.base.read_u8().await?;
            if version != 0 {
                return Err(MolluskError::VersionMismatch(0, version));
            }

            // record type check
            let record_type = stream.base.read_u8().await?;
            if record_type != RecordType::HandshakeFinish as u8 {
                return Err(MolluskError::RecordTypeMismatch(
                    RecordType::HandshakeFinish as u8,
                    record_type,
                ));
            }

            // length check
            let record_length = stream.base.read_u16_le().await?;
            if record_length != 72 {
                return Err(MolluskError::ParseError);
            }

            // read
            let mut msg = vec![0u8; 4 + record_length as usize].into_boxed_slice();
            msg[0] = version;
            msg[1] = record_type;
            (&mut msg[2..4]).write_all(&record_length.to_le_bytes())?;
            stream.base.read_exact(&mut msg[4..]).await?;

            unsafe {
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    msg.as_mut_ptr().add(28),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    msg.as_ptr().add(28),
                    48,
                    msg.as_ptr(),
                    28,
                    msg.as_ptr().add(4),
                    client_handshake_key.as_ptr(),
                )
            }
            .error(MolluskError::DecryptFailed)?;

            let mut client_finished_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    client_finished_key.as_mut_ptr(),
                    32,
                    1,
                    "finished".as_ptr().cast(),
                    client_handshake_key.as_ptr(),
                );
            }

            unsafe {
                crypto_auth_verify(
                    msg.as_ptr().add(28),
                    session_hasher.clone().finalize().as_ptr(),
                    32,
                    client_finished_key.as_ptr(),
                )
            }
            .error(MolluskError::AuthFailed)?;

            session_hasher.update(&msg[..60]);
        }

        {
            // calculate rx/tx keys

            let mut derived_key = [0u8; 32];
            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    derived_key.as_mut_ptr(),
                    32,
                    1,
                    "derivedk".as_ptr().cast(),
                    handshake_secret.as_ptr(),
                );
            }

            let application_secret = Hasher::new()
                .init()
                .update(&derived_key)
                .update(&session_hasher.finalize())
                .finalize();

            unsafe {
                // cannot fail
                crypto_kdf_derive_from_key(
                    stream.rx_key.as_mut_ptr(),
                    32,
                    1,
                    "clientap".as_ptr().cast(),
                    application_secret.as_ptr(),
                );
                // cannot fail
                crypto_kdf_derive_from_key(
                    stream.tx_key.as_mut_ptr(),
                    32,
                    2,
                    "serverap".as_ptr().cast(),
                    application_secret.as_ptr(),
                );
            }
        }

        // FIN

        Ok(stream)
    }
}

impl<Base: AsyncWrite + AsyncRead + Unpin> AsyncRead for MolluskStream<Base> {
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
                let base = std::pin::pin!(&mut stream.base);

                // do not have enough data, try to read more
                let len = stream.buf.len();
                let mut buf = ReadBuf::new(&mut stream.buf[(len - stream.pending)..]);
                std::task::ready!(base.poll_read(cx, &mut buf))?;

                // check eof
                if buf.filled().is_empty() {
                    return std::task::Poll::Ready(Ok(()));
                }
                stream.pending -= buf.filled().len();
            }

            // pending should always be 0 after this point

            if !stream.mode {
                // we have read the header
                if stream.buf[0] != 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "mismatched version",
                    )));
                }
                if stream.buf[1] != RecordType::Data as u8 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected record",
                    )));
                }

                let record_length = u16::from_le_bytes(stream.buf[2..4].try_into().unwrap());

                // set up to read record
                stream.pending = record_length.into();
                stream.pending_read = stream.pending - 40;
                stream.mode = true;

                let mut new_buf = vec![0u8; 4 + record_length as usize].into_boxed_slice();
                new_buf[0..4].copy_from_slice(&stream.buf);
                stream.buf = new_buf;
            } else {
                // we have the data
                let res = unsafe {
                    crypto_aead_xchacha20poly1305_ietf_decrypt(
                        stream.buf.as_mut_ptr().add(28),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        stream.buf.as_ptr().add(28),
                        (stream.buf.len() - 28) as u64,
                        stream.buf.as_ptr(),
                        28,
                        stream.buf.as_ptr().add(4),
                        stream.rx_key.as_ptr(),
                    )
                };
                if res != 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decryption failure",
                    )));
                }

                if buf.remaining() < stream.pending_read {
                    // can transmit only partial
                    let read_start = stream.buf.len() - 16 - stream.pending_read;
                    stream.pending_read -= buf.remaining();
                    let read_end = read_start + buf.remaining();
                    buf.put_slice(&stream.buf[read_start..read_end]);
                } else {
                    // can transmit full
                    let read_start = stream.buf.len() - 16 - stream.pending_read;
                    let read_end = read_start + stream.pending_read;
                    buf.put_slice(&stream.buf[read_start..read_end]);

                    stream.buf = vec![0u8; 4].into_boxed_slice();
                    stream.pending = 4;
                    stream.mode = false;
                    stream.pending_read = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }
        }
    }
}

impl<Base: AsyncWrite + AsyncRead + Unpin> AsyncWrite for MolluskStream<Base> {
    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // flush existing data first
        std::task::ready!(self.as_mut().poll_flush(cx))?;

        // construct new buf
        // up to 16000 bytes at once
        let len = std::cmp::min(buf.len(), 16000) as u16;
        let mut new_buf = vec![0u8; 4 + 24 + len as usize + 16].into_boxed_slice();

        new_buf[0] = 0;
        new_buf[1] = RecordType::Data as u8;
        (&mut new_buf[2..4]).write_all(&(len + 40).to_le_bytes())?;
        unsafe {
            // cannot fail
            randombytes_buf(new_buf.as_mut_ptr().add(4).cast(), 24);
        };
        new_buf[28..(28 + len as usize)].copy_from_slice(&buf[0..len as usize]);

        unsafe {
            // cannot fail
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                new_buf.as_mut_ptr().add(28),
                std::ptr::null_mut(),
                new_buf.as_ptr().add(28),
                len as u64,
                new_buf.as_ptr(),
                28,
                std::ptr::null(),
                new_buf.as_ptr().add(4),
                self.tx_key.as_ptr(),
            );
        };

        // queue up new buf
        self.wbuf = new_buf;
        self.pending_write = self.wbuf.len();

        std::task::Poll::Ready(Ok(len as usize))
    }

    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let stream = self.get_mut();

        while stream.pending_write != 0 {
            let base = std::pin::pin!(&mut stream.base);

            // try to send existing messages first
            let start = stream.wbuf.len() - stream.pending_write;
            let size = std::task::ready!(base.poll_write(cx, &stream.wbuf[start..]))?;
            stream.pending_write -= size;
        }

        std::task::Poll::Ready(Ok(()))
    }

    // IMPORTANT: Return Pending only as a direct result of base returning Pending
    // Ensures wakers are set up correctly
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let stream = self.get_mut();
        let base = std::pin::pin!(&mut stream.base);

        base.poll_shutdown(cx)
    }
}
