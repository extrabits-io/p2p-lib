//! Auth implementation for bore client and server.

use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Result};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::shared::{ClientMessage, Delimited, ServerMessage};

const DOMAIN: &[u8] = b"P2P_RELAY_V1_CHALLENGE";

fn generate_challenge() -> (Vec<u8>, u64) {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut challenge = DOMAIN.to_vec();
    challenge.extend_from_slice(&timestamp.to_be_bytes());
    challenge.extend_from_slice(&nonce);

    (challenge, timestamp)
}

/// Struct to answer server authentication challenges
pub struct ClientAuthenticator {
    signing_key: SigningKey,
}

impl ClientAuthenticator {
    /// Instanciate a new ClientAuthenticator
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generate a reply message for a challenge.
    pub fn answer(&self, challenge: &[u8]) -> String {
        let signature = self.signing_key.sign(challenge);
        signature.to_string()
    }

    /// As the client, answer a challenge to attempt to authenticate with the server.
    pub async fn client_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Delimited<T>,
    ) -> Result<()> {
        let challenge = match stream.recv_timeout().await? {
            Some(ServerMessage::Challenge(challenge)) => challenge,
            _ => bail!("expected authentication challenge, but no challenge was sent"),
        };
        let public_key = self
            .signing_key
            .verifying_key()
            .to_public_key_der()?
            .to_vec();
        let signature = self.answer(&challenge);
        stream
            .send(ClientMessage::Authenticate {
                public_key,
                signature,
            })
            .await?;
        Ok(())
    }
}

/// Struct for authenticating clients that have a signing key.
pub struct ServerAuthenticator {
    allowed_clients: Vec<VerifyingKey>,
}

impl ServerAuthenticator {
    /// Instanciate a new ServerAuthenticator
    pub fn new(allowed_clients: Vec<VerifyingKey>) -> Self {
        Self { allowed_clients }
    }

    /// Validate a reply to a challenge.
    pub fn validate_signature(
        &self,
        verifying_key: &VerifyingKey,
        challenge: &[u8],
        signature_str: &str,
        timestamp: u64,
    ) -> Result<()> {
        ensure!(
            self.allowed_clients.contains(verifying_key),
            "Invalid client key"
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ensure!((now - timestamp) < 30, "Challenge has expired");
        let signature = Signature::from_str(signature_str)?;
        // use verify_strict to mitigate weak key attacks
        // https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html#strict-verification
        verifying_key.verify_strict(challenge, &signature)?;
        Ok(())
    }

    /// As the server, send a challenge to the client and validate their response.
    pub async fn server_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Delimited<T>,
    ) -> Result<()> {
        let (challenge, timestamp) = generate_challenge();
        tracing::debug!("Sending challenge: {:?}", &challenge);
        stream
            .send(ServerMessage::Challenge(challenge.clone()))
            .await?;
        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate {
                public_key,
                signature,
            }) => {
                tracing::debug!("Received answer: {:?} {}", &public_key, &signature);
                let verifying_key = VerifyingKey::from_public_key_der(&public_key)?;
                self.validate_signature(&verifying_key, &challenge, &signature, timestamp)?;
                Ok(())
            }
            _ => bail!("server requires secret, but no secret was provided"),
        }
    }
}
