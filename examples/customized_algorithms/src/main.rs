use ssh::algorithm;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than INFO (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let mut session = ssh::create_session_without_default()
        .username("ubuntu")
        .private_key_path("./id_rsa")
        .password("password")
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
        .del_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_pubkey_algorithms(algorithm::PubKey::SshRsa)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .del_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha1)
        .connect("127.0.0.1:22")
        .unwrap()
        .run_local();

    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
    // Close session.
    session.close();
}
