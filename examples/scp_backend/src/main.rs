
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
    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect("127.0.0.1:22")
        .unwrap()
        .run_backend();

    // upload a file
    let scp = session.open_scp().unwrap();
    // currently upload cannot automatically run in the backend
    scp.upload("./src/main.rs", "./").unwrap();
    assert_file("/home/ubuntu/main.rs");

    // download a file
    let mut scp = session.open_scp().unwrap();
    scp.start_download("./", "test/a").unwrap();
    println!("Doing some other things");
    assert_no_file("./a");
    scp.end_download().unwrap();
    assert_file("./a");

    session.close();
}

fn assert_file(filename: &str) {
    let file = std::path::Path::new(filename);

    println!("Assert file {}", filename);
    assert!(file.exists());

    std::fs::remove_file(file).unwrap();
}

fn assert_no_file(filename: &str) {
    let file = std::path::Path::new(filename);

    println!("Assert no file {}", filename);
    assert!(!file.exists());
}
