use anyhow::Result;
use bore_cli::{
    auth::{ClientAuthenticator, ServerAuthenticator},
    shared::{generate_signing_key, Delimited},
};
use tokio::io::{self};

#[tokio::test]
async fn auth_handshake() -> Result<()> {
    let key = generate_signing_key();
    let server_auth = ServerAuthenticator::new(vec![key.verifying_key()]);
    let client_auth = ClientAuthenticator::new(key);

    let (client, server) = io::duplex(8); // Ensure correctness with limited capacity.
    let mut client = Delimited::new(client);
    let mut server = Delimited::new(server);

    tokio::try_join!(
        client_auth.client_handshake(&mut client),
        server_auth.server_handshake(&mut server),
    )?;

    Ok(())
}

#[tokio::test]
async fn auth_handshake_fail() {
    let key1 = generate_signing_key();
    let key2 = generate_signing_key();
    let client_auth = ClientAuthenticator::new(key1);
    let server_auth = ServerAuthenticator::new(vec![key2.verifying_key()]);

    let (client, server) = io::duplex(8); // Ensure correctness with limited capacity.
    let mut client = Delimited::new(client);
    let mut server = Delimited::new(server);

    let result = tokio::try_join!(
        client_auth.client_handshake(&mut client),
        server_auth.server_handshake(&mut server),
    );
    assert!(result.is_err());
}
