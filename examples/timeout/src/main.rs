
use std::net::TcpListener;
use std::time::Duration;
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

    let _listener = TcpListener::bind("127.0.0.1:7777").unwrap();
    match ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .timeout(Some(Duration::from_secs(5)))
        .connect("127.0.0.1:7777")
    {
        Err(e) => println!("Got error {}", e),
        _ => unreachable!(),
    }
}
