//! Client implementation for the `bore` service.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tracing::{error, info, info_span, warn, Instrument};

use crate::auth::ClientAuthenticator;
use crate::shared::{ClientMessage, Delimited, PeerKey, ServerMessage, NETWORK_TIMEOUT};

/// Proxy that performs the bi-directional streaming between server and client
struct Proxy {
    to: String,
    local_host: String,
    local_port: u16,
    auth: ClientAuthenticator,
    control_port: u16,
}

impl Proxy {
    async fn handle_connection(&self, peer_key: PeerKey) -> Result<()> {
        let mut remote_conn =
            Delimited::new(connect_with_timeout(&self.to[..], self.control_port).await?);

        self.auth.client_handshake(&mut remote_conn).await?;
        remote_conn.send(ClientMessage::Accept(peer_key)).await?;
        let mut local_conn = connect_with_timeout(&self.local_host, self.local_port).await?;

        let mut parts = remote_conn.into_parts();
        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");

        local_conn.write_all(&parts.read_buf).await?;
        tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
        Ok(())
    }
}

/// State structure for the client.
pub struct Client {
    public_key: PeerKey,
    /// Proxy to handle remote connections.
    proxy: Arc<Proxy>,
}

impl Client {
    /// Create a new client.
    pub fn new(
        local_host: &str,
        local_port: u16,
        to: &str,
        control_port: u16,
        signing_key: SigningKey,
    ) -> Result<Self, anyhow::Error> {
        let public_key = PeerKey::from_signing_key(&signing_key)?;
        let auth = ClientAuthenticator::new(signing_key);
        Ok(Client {
            public_key,
            proxy: Arc::new(Proxy {
                to: to.to_string(),
                local_host: local_host.to_string(),
                local_port,
                control_port,
                auth,
            }),
        })
    }

    /// Connect to the server.
    pub async fn connect(&self) -> Result<Delimited<TcpStream>> {
        let mut stream =
            Delimited::new(connect_with_timeout(&self.proxy.to, self.proxy.control_port).await?);

        self.proxy.auth.client_handshake(&mut stream).await?;
        stream
            .send(ClientMessage::Hello(self.public_key, self.proxy.local_port))
            .await?;
        let remote_port = match stream.recv_timeout().await? {
            Some(ServerMessage::Hello(remote_port)) => remote_port,
            Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
            Some(ServerMessage::Challenge(_)) => {
                bail!("server requires authentication, but no client secret was provided");
            }
            Some(_) => bail!("unexpected initial non-hello message"),
            None => bail!("unexpected EOF"),
        };

        info!(remote_port, "connected to server");
        info!("listening at {}:{}", self.proxy.to, remote_port);

        Ok(stream)
    }

    /// Start the client, listening for new connections using a mutable reference.
    pub async fn listen(&self, mut conn: Delimited<TcpStream>) -> Result<()> {
        loop {
            match conn.recv().await? {
                Some(ServerMessage::Hello(_)) => warn!("unexpected hello"),
                Some(ServerMessage::Challenge(_)) => warn!("unexpected challenge"),
                Some(ServerMessage::Heartbeat) => (),
                Some(ServerMessage::Connection(id)) => {
                    // Clone the Arc to move into the spawned task
                    let proxy = Arc::clone(&self.proxy);
                    tokio::spawn(
                        async move {
                            info!("new connection");
                            match proxy.handle_connection(id).await {
                                Ok(_) => info!("connection exited"),
                                Err(err) => warn!(%err, "connection exited with error"),
                            }
                        }
                        .instrument(info_span!("proxy", %id)),
                    );
                }
                Some(ServerMessage::Error(err)) => error!(%err, "server error"),
                None => return Ok(()),
            }
        }
    }
}

async fn connect_with_timeout(to: &str, port: u16) -> Result<TcpStream> {
    match timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port))).await {
        Ok(res) => res,
        Err(err) => Err(err.into()),
    }
    .with_context(|| format!("could not connect to {to}:{port}"))
}
