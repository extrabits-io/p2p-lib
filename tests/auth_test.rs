use anyhow::Result;
use bore_cli::{
    auth::Authenticator,
    shared::{generate_signing_key, Delimited},
};
use tokio::io::{self};

#[tokio::test]
async fn auth_handshake() -> Result<()> {
    let auth = Authenticator::new(generate_signing_key());

    let (client, server) = io::duplex(8); // Ensure correctness with limited capacity.
    let mut client = Delimited::new(client);
    let mut server = Delimited::new(server);

    tokio::try_join!(
        auth.client_handshake(&mut client),
        auth.server_handshake(&mut server),
    )?;

    Ok(())
}

// #[tokio::test]
// async fn auth_handshake_fail() {
//     let auth = Authenticator::new(generate_signing_key());
//     let auth2 = Authenticator::new(generate_signing_key());

//     let (client, server) = io::duplex(8); // Ensure correctness with limited capacity.
//     let mut client = Delimited::new(client);
//     let mut server = Delimited::new(server);

//     let result = tokio::try_join!(
//         auth.client_handshake(&mut client),
//         auth2.server_handshake(&mut server),
//     );
//     assert!(result.is_err());
// }
