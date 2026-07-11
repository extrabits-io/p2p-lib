//! Server implementation for the `bore` service.

use std::net::{IpAddr, Ipv4Addr};
use std::{io, ops::RangeInclusive, sync::Arc, time::Duration};

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tracing::{info, info_span, warn, Instrument};

use crate::auth::ServerAuthenticator;
use crate::shared::{ClientMessage, Delimited, PeerInfo, PeerKey, ServerMessage};

/// State structure for the server.
pub struct Server {
    /// Range of TCP ports that can be forwarded.
    port_range: RangeInclusive<u16>,

    /// Authenticator used to authenticate clients.
    auth: ServerAuthenticator,

    /// Concurrent map of IDs to incoming connections.
    conns: Arc<DashMap<PeerKey, TcpStream>>,

    /// IP address where the control server will bind to.
    bind_addr: IpAddr,

    /// IP address where tunnels will listen on.
    bind_tunnels: IpAddr,

    control_port: u16,

    /// Callback invoked with the `PeerKey` and port whenever a new peer connects.
    on_peer_connected: Option<Arc<dyn Fn(PeerInfo) + Send + Sync>>,

    /// Callback invoked when a peer disconnects or times out.
    on_peer_disconnected: Option<Arc<dyn Fn(PeerKey) + Send + Sync>>,
}

impl Server {
    /// Create a new server with a specified minimum port number.
    pub fn new(
        control_port: u16,
        peer_port_range: RangeInclusive<u16>,
        allowed_clients: Vec<PeerKey>,
    ) -> Self {
        assert!(peer_port_range.len() > 0, "Must provide at least one port");
        Server {
            port_range: peer_port_range,
            conns: Arc::new(DashMap::new()),
            auth: ServerAuthenticator::new(allowed_clients),
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            control_port,
            on_peer_connected: None,
            on_peer_disconnected: None,
        }
    }

    /// Set the IP address where the control server will bind to.
    pub fn set_bind_addr(&mut self, bind_addr: IpAddr) {
        self.bind_addr = bind_addr;
    }

    /// Set the IP address where tunnels will listen on.
    pub fn set_bind_tunnels(&mut self, bind_tunnels: IpAddr) {
        self.bind_tunnels = bind_tunnels;
    }

    /// Set a callback to be invoked with the `PeerKey` and port of each newly connected peer.
    pub fn set_on_peer_connected<F>(&mut self, callback: F)
    where
        F: Fn(PeerInfo) + Send + Sync + 'static,
    {
        self.on_peer_connected = Some(Arc::new(callback));
    }

    /// Set a callback to be invoked with the `PeerKey` of peers that disconnect.
    pub fn set_on_peer_disconnected<F>(&mut self, callback: F)
    where
        F: Fn(PeerKey) + Send + Sync + 'static,
    {
        self.on_peer_disconnected = Some(Arc::new(callback));
    }

    /// Start the server, listening for new connections.
    pub async fn listen(self) -> Result<()> {
        let this = Arc::new(self);
        let listener = TcpListener::bind((this.bind_addr, this.control_port)).await?;
        info!(
            "server listening at {}:{}",
            &this.bind_addr, &this.control_port
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = Arc::clone(&this);
            tokio::spawn(
                async move {
                    info!("incoming connection");
                    if let Err(err) = this.handle_connection(stream).await {
                        warn!(%err, "connection exited with error");
                    } else {
                        info!("connection exited");
                    }
                }
                .instrument(info_span!("control", ?addr)),
            );
        }
    }

    async fn create_listener(&self, port: u16) -> Result<TcpListener, &'static str> {
        let try_bind = |port: u16| async move {
            TcpListener::bind((self.bind_tunnels, port))
                .await
                .map_err(|err| match err.kind() {
                    io::ErrorKind::AddrInUse => "port already in use",
                    io::ErrorKind::PermissionDenied => "permission denied",
                    _ => "failed to bind to port",
                })
        };
        if port > 0 {
            // Client requests a specific port number.
            if !self.port_range.contains(&port) {
                return Err("client port number not in allowed range");
            }
            try_bind(port).await
        } else {
            // Client requests any available port in range.
            //
            // In this case, we bind to 150 random port numbers. We choose this value because in
            // order to find a free port with probability at least 1-δ, when ε proportion of the
            // ports are currently available, it suffices to check approximately -2 ln(δ) / ε
            // independently and uniformly chosen ports (up to a second-order term in ε).
            //
            // Checking 150 times gives us 99.999% success at utilizing 85% of ports under these
            // conditions, when ε=0.15 and δ=0.00001.
            for _ in 0..150 {
                let port = fastrand::u16(self.port_range.clone());
                match try_bind(port).await {
                    Ok(listener) => return Ok(listener),
                    Err(_) => continue,
                }
            }
            Err("failed to find an available port")
        }
    }

    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        let mut stream = Delimited::new(stream);
        if let Err(err) = self.auth.server_handshake(&mut stream).await {
            warn!(%err, "server handshake failed");
            stream.send(ServerMessage::Error(err.to_string())).await?;
            return Ok(());
        }

        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate {
                public_key: _,
                signature: _,
            }) => {
                warn!("unexpected authenticate");
                Ok(())
            }
            Some(ClientMessage::Hello(public_key, port)) => {
                let listener = match self.create_listener(port).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        stream.send(ServerMessage::Error(err.into())).await?;
                        return Ok(());
                    }
                };
                let host = listener.local_addr()?.ip();
                let port = listener.local_addr()?.port();
                info!(?host, ?port, "new client");
                if let Some(callback) = &self.on_peer_connected {
                    callback((public_key, port));
                }
                stream.send(ServerMessage::Hello(port)).await?;

                loop {
                    if stream.send(ServerMessage::Heartbeat).await.is_err() {
                        // Assume that the TCP connection has been dropped.
                        break;
                    }
                    const TIMEOUT: Duration = Duration::from_millis(500);
                    if let Ok(result) = timeout(TIMEOUT, listener.accept()).await {
                        let (stream2, addr) = result?;
                        info!(?addr, ?port, "new connection");

                        let conns = Arc::clone(&self.conns);

                        conns.insert(public_key, stream2);
                        tokio::spawn(async move {
                            // Remove stale entries to avoid memory leaks.
                            sleep(Duration::from_secs(10)).await;
                            if conns.remove(&public_key).is_some() {
                                warn!(%public_key, "removed stale connection");
                            }
                        });
                        stream.send(ServerMessage::Connection(public_key)).await?;
                    }
                }

                if let Some(callback) = &self.on_peer_disconnected {
                    callback(public_key);
                }

                Ok(())
            }
            Some(ClientMessage::Accept(public_key)) => {
                info!(%public_key, "forwarding connection");
                match self.conns.remove(&public_key) {
                    Some((_, mut stream2)) => {
                        let mut parts = stream.into_parts();
                        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                        stream2.write_all(&parts.read_buf).await?;
                        tokio::io::copy_bidirectional(&mut parts.io, &mut stream2).await?;
                    }
                    None => warn!(%public_key, "missing connection"),
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
