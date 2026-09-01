//! Shared data structures, utilities, and protocol definitions.

use std::fmt::{self, Display};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{AnyDelimiterCodec, Framed, FramedParts};
use tracing::trace;
use uuid::Uuid;

/// Maximum byte length for a JSON frame in the stream.
pub const MAX_FRAME_LENGTH: usize = 512;

/// Timeout for network connections and initial protocol messages.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

/// Wrapper for the DER-encoded bytes of a Ed25519 public key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerKey(pub [u8; 44]);

impl Serialize for PeerKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(44)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for PeerKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PeerKey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 44-byte array")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; 44];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(PeerKey(arr))
            }
        }
        deserializer.deserialize_tuple(44, Visitor)
    }
}

impl PeerKey {
    /// Create a new instance from a unknown-length Vec of bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, anyhow::Error> {
        let len = bytes.len();
        let public_key_der: [u8; 44] = bytes
            .try_into()
            .map_err(|_| anyhow!("expected a 44-byte public key, got {len} bytes"))?;
        Ok(PeerKey(public_key_der))
    }

    /// Create a new instance from a `SigningKey`.
    pub fn from_signing_key<'a>(value: &'a SigningKey) -> Result<Self, anyhow::Error> {
        let public_key: [u8; 44] = value
            .verifying_key()
            .to_public_key_der()?
            .as_bytes()
            .try_into()?;
        Ok(PeerKey(public_key))
    }

    /// Build a `VerifyingKey` instance from this instance.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, anyhow::Error> {
        VerifyingKey::from_public_key_der(&self.0).map_err(|e| anyhow!(e))
    }
}

impl Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Fields needed to route incoming requests to a unique peer.
pub type PeerInfo = (PeerKey, u16);

/// A message from the client on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Response to an authentication challenge from the server.
    Authenticate {
        /// The client's public key; known by the server
        public_key: PeerKey,
        /// The server's challenge, signed by the client's signing key
        signature: String,
    },

    /// Initial client message specifying a port to forward.
    Hello(PeerKey, u16),

    /// Accepts an incoming TCP connection, using this stream as a proxy.
    Accept(PeerKey, Uuid),
}

/// A message from the server on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Authentication challenge, sent as the first message, if enabled.
    Challenge(Vec<u8>),

    /// Response to a client's initial message, with actual public port.
    Hello(u16),

    /// No-op used to test if the client is still reachable.
    Heartbeat,

    /// Asks the client to accept a forwarded TCP connection.
    Connection(Uuid),

    /// Indicates a server error that terminates the connection.
    Error(String),
}

/// Transport stream with JSON frames delimited by null characters.
pub struct Delimited<U>(Framed<U, AnyDelimiterCodec>);

impl<U: AsyncRead + AsyncWrite + Unpin> Delimited<U> {
    /// Construct a new delimited stream.
    pub fn new(stream: U) -> Self {
        let codec = AnyDelimiterCodec::new_with_max_length(vec![0], vec![0], MAX_FRAME_LENGTH);
        Self(Framed::new(stream, codec))
    }

    /// Read the next null-delimited JSON instruction from a stream.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        trace!("waiting to receive json message");
        if let Some(next_message) = self.0.next().await {
            let byte_message = next_message.context("frame error, invalid byte length")?;
            let serialized_obj =
                serde_json::from_slice(&byte_message).context("unable to parse message")?;
            Ok(serialized_obj)
        } else {
            Ok(None)
        }
    }

    /// Read the next null-delimited JSON instruction, with a default timeout.
    ///
    /// This is useful for parsing the initial message of a stream for handshake or
    /// other protocol purposes, where we do not want to wait indefinitely.
    pub async fn recv_timeout<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        timeout(NETWORK_TIMEOUT, self.recv())
            .await
            .context("timed out waiting for initial message")?
    }

    /// Send a null-terminated JSON instruction on a stream.
    pub async fn send<T: Serialize>(&mut self, msg: T) -> Result<()> {
        trace!("sending json message");
        self.0.send(serde_json::to_string(&msg)?).await?;
        Ok(())
    }

    /// Consume this object, returning current buffers and the inner transport.
    pub fn into_parts(self) -> FramedParts<U, AnyDelimiterCodec> {
        self.0.into_parts()
    }
}

/// Generate a new signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}
