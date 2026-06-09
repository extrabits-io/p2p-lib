use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bore_cli::shared::{generate_signing_key, Delimited};
use bore_cli::{client::Client, server::Server};
use ed25519_dalek::{SigningKey, VerifyingKey};
use lazy_static::lazy_static;
use rstest::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time;

lazy_static! {
    /// Guard to make sure that tests are run serially, not concurrently.
    static ref SERIAL_GUARD: Mutex<()> = Mutex::new(());
}

const PORT_RANGE_START: u16 = 3000;
const PORT_RANGE_END: u16 = 3050;

/// Spawn the server, giving some time for the control port TcpListener to start.
async fn spawn_server(secret: Option<VerifyingKey>) {
    let allowed_clients = secret.map(|key| vec![key]);
    tokio::spawn(Server::new(PORT_RANGE_START..=PORT_RANGE_END, allowed_clients).listen());
    time::sleep(Duration::from_millis(50)).await;
}

/// Spawns a client with randomly assigned ports, returning the listener and remote address.
async fn spawn_client(
    secret: Option<SigningKey>,
) -> Result<(Client, Delimited<TcpStream>, TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(format!("localhost:{}", PORT_RANGE_START + 1)).await?;
    let local_port = listener.local_addr()?.port();
    let client = Client::new(
        "localhost",
        local_port,
        "localhost",
        PORT_RANGE_START,
        secret,
    );
    let remote_addr = ([127, 0, 0, 1], PORT_RANGE_START).into();
    let stream = client.connect().await?;
    Ok((client, stream, listener, remote_addr))
}

#[rstest]
#[tokio::test]
async fn basic_proxy(#[values(false, true)] should_use_key: bool) -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    let client_key = if should_use_key {
        Some(generate_signing_key())
    } else {
        None
    };
    let server_key = client_key.clone().map(|key| key.verifying_key());
    spawn_server(server_key).await;
    let (client, stream, listener, addr) = spawn_client(client_key).await?;
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
#[case(false, true)]
#[case(true, false)]
#[tokio::test]
async fn mismatched_secret(
    #[case] should_use_server_key: bool,
    #[case] should_use_client_key: bool,
) {
    let _guard = SERIAL_GUARD.lock().await;
    let key = generate_signing_key();
    let server_key = if should_use_server_key {
        Some(key.verifying_key())
    } else {
        None
    };
    let client_key = if should_use_client_key {
        Some(key)
    } else {
        None
    };

    spawn_server(server_key).await;
    assert!(spawn_client(client_key).await.is_err());
}

#[tokio::test]
async fn invalid_address() -> Result<()> {
    // We don't need the serial guard for this test because it doesn't create a server.
    async fn check_address(to: &str, use_secret: bool) -> Result<()> {
        let client = Client::new(
            "localhost",
            5000,
            to,
            0,
            use_secret.then_some(generate_signing_key()),
        );
        match client.connect().await {
            Ok(_) => Err(anyhow!("expected error for {to}, use_secret={use_secret}")),
            Err(_) => Ok(()),
        }
    }
    tokio::try_join!(
        check_address("google.com", false),
        check_address("google.com", true),
        check_address("nonexistent.domain.for.demonstration", false),
        check_address("nonexistent.domain.for.demonstration", true),
        check_address("malformed !$uri$%", false),
        check_address("malformed !$uri$%", true),
    )?;
    Ok(())
}

#[tokio::test]
async fn very_long_frame() -> Result<()> {
    let _guard = SERIAL_GUARD.lock().await;

    spawn_server(None).await;
    let mut attacker = TcpStream::connect(("localhost", PORT_RANGE_START)).await?;

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
    let _ = Server::new(min_port..=max_port, None);
}

#[tokio::test]
async fn half_closed_tcp_stream() -> Result<()> {
    // Check that "half-closed" TCP streams will not result in spontaneous hangups.
    let _guard = SERIAL_GUARD.lock().await;

    spawn_server(None).await;
    let (_, _, listener, addr) = spawn_client(None).await?;

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
