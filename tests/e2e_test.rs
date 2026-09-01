use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use lazy_static::lazy_static;
use p2p_lib::shared::{generate_signing_key, Delimited, PeerKey};
use p2p_lib::{client::Client, server::Server};
use rstest::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time;

lazy_static! {
    /// Guard to make sure that tests are run serially, not concurrently.
    static ref SERIAL_GUARD: Mutex<()> = Mutex::new(());
}

/// Spawn the server, giving some time for the control port TcpListener to start.
async fn spawn_server(peer_key: PeerKey) -> Result<(u16, u16)> {
    let listener1 = TcpListener::bind("localhost:0").await?;
    let port1 = listener1.local_addr()?.port();
    let listener2 = TcpListener::bind("localhost:0").await?;
    let port2 = listener2.local_addr()?.port();
    drop(listener1);
    drop(listener2);
    let (control_port, port_range) = if port2 > port1 {
        (port1, port2..=port2)
    } else {
        (port2, port1..=port1)
    };
    print!("Control port {control_port}; port range: {:?}", &port_range);

    let client_port = port_range.clone().into_iter().next().unwrap();
    let allowed_clients = vec![peer_key];
    let mut server = Server::new(control_port, port_range, allowed_clients);
    server.set_bind_tunnels(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)));
    tokio::spawn(server.listen());
    time::sleep(Duration::from_millis(50)).await;

    Ok((control_port, client_port))
}

/// Spawns a client with randomly assigned ports, returning the listener and remote address.
async fn spawn_client(
    control_port: u16,
    local_port: u16,
    signing_key: SigningKey,
) -> Result<(Client, Delimited<TcpStream>, TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(format!("localhost:{local_port}")).await?;
    let client = Client::new(
        "localhost",
        local_port,
        "localhost",
        control_port,
        signing_key,
    )?;
    let remote_addr = ([127, 0, 0, 2], local_port).into();
    let stream = client.connect().await?;
    Ok((client, stream, listener, remote_addr))
}

#[rstest]
#[tokio::test]
async fn basic_proxy() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    let client_key = generate_signing_key();
    let peer_key = PeerKey::from_signing_key(&client_key)?;
    let (control_port, client_port) = spawn_server(peer_key).await?;
    let (client, stream, listener, addr) =
        spawn_client(control_port, client_port, client_key).await?;
    tokio::spawn(async move { client.listen(stream).await });

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello world");

        stream.write_all(b"I can send a message too!").await?;
        anyhow::Ok(())
    });

    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(b"hello world").await?;

    let mut buf = [0u8; 25];
    stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"I can send a message too!");

    // Ensure that the client end of the stream is closed now.
    assert_eq!(stream.read(&mut buf).await?, 0);

    // Also ensure that additional connections do not produce any data.
    let mut stream = TcpStream::connect(addr).await?;
    assert_eq!(stream.read(&mut buf).await?, 0);

    Ok(())
}

#[rstest]
#[tokio::test]
async fn mismatched_secret() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;
    let client_key = generate_signing_key();
    let other_peer_key = PeerKey::from_signing_key(&generate_signing_key())?;
    let (control_port, client_port) = spawn_server(other_peer_key).await?;
    assert!(spawn_client(control_port, client_port, client_key)
        .await
        .is_err());

    Ok(())
}

#[tokio::test]
async fn invalid_address() -> Result<()> {
    // We don't need the serial guard for this test because it doesn't create a server.
    async fn check_address(to: &str) -> Result<()> {
        let client = Client::new("localhost", 5000, to, 0, generate_signing_key())?;
        match client.connect().await {
            Ok(_) => Err(anyhow!("expected error for {to}")),
            Err(_) => Ok(()),
        }
    }
    tokio::try_join!(
        check_address("google.com"),
        check_address("nonexistent.domain.for.demonstration"),
        check_address("malformed !$uri$%"),
    )?;
    Ok(())
}

#[tokio::test]
async fn very_long_frame() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    let peer_key = PeerKey::from_signing_key(&generate_signing_key())?;
    let (control_port, _) = spawn_server(peer_key).await?;
    let mut attacker = TcpStream::connect(("localhost", control_port)).await?;

    // Slowly send a very long frame.
    for _ in 0..10 {
        let result = attacker.write_all(&[42u8; 100000]).await;
        if result.is_err() {
            return Ok(());
        }
        time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not exit after a 1 MB frame");
}

#[test]
#[should_panic]
fn empty_port_range() {
    let min_port = 5000;
    let max_port = 3000;
    let _ = Server::new(2000, min_port..=max_port, vec![]);
}

#[tokio::test]
async fn half_closed_tcp_stream() -> Result<()> {
    // Check that "half-closed" TCP streams will not result in spontaneous hangups.
    let _guard = SERIAL_GUARD.lock().await;

    let client_key = generate_signing_key();
    let peer_key = PeerKey::from_signing_key(&client_key)?;
    let (control_port, client_port) = spawn_server(peer_key).await?;
    let (_, _, listener, addr) = spawn_client(control_port, client_port, client_key).await?;

    let (mut cli, (mut srv, _)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())?;

    // Send data before half-closing one of the streams.
    let mut buf = b"message before shutdown".to_vec();
    cli.write_all(&buf).await?;

    // Only close the write half of the stream. This is a half-closed stream. In the
    // TCP protocol, it is represented as a FIN packet on one end. The entire stream
    // is only closed after two FINs are exchanged and ACKed by the other end.
    cli.shutdown().await?;

    srv.read_exact(&mut buf).await?;
    assert_eq!(buf, b"message before shutdown");
    assert_eq!(srv.read(&mut buf).await?, 0); // EOF

    // Now make sure that the other stream can still send data, despite
    // half-shutdown on client->server side.
    let mut buf = b"hello from the other side!".to_vec();
    srv.write_all(&buf).await?;
    cli.read_exact(&mut buf).await?;
    assert_eq!(buf, b"hello from the other side!");

    // We don't have to think about CLOSE_RD handling because that's not really
    // part of the TCP protocol, just the POSIX streams API. It is implemented by
    // the OS ignoring future packets received on that stream.

    Ok(())
}
