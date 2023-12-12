
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
        .run_local();

    // upload a file
    let scp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./").unwrap();
    assert_file("/home/ubuntu/main.rs");

    // upload with a rename
    let scp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./abc").unwrap();
    assert_file("/home/ubuntu/abc");

    // upload to an implicit dir
    let scp = session.open_scp().unwrap();
    scp.upload("./src/main.rs", "./test").unwrap();
    assert_file("/home/ubuntu/test/main.rs");

    // upload a dir
    let scp = session.open_scp().unwrap();
    scp.upload("./src", "./test").unwrap();
    assert_file("/home/ubuntu/test/src/main.rs");
    assert_dir("/home/ubuntu/test/src");

    // upload a with a rename
    let scp = session.open_scp().unwrap();
    scp.upload("./src", "./crs").unwrap();
    assert_file("/home/ubuntu/crs/main.rs");
    assert_dir("/home/ubuntu/crs");

    // download a file
    let scp = session.open_scp().unwrap();
    scp.download("./", "test/a").unwrap();
    assert_file("./a");

    // download with a rename
    let scp = session.open_scp().unwrap();
    scp.download("./b", "test/a").unwrap();
    assert_file("./b");

    // download to an implicit dir
    let scp = session.open_scp().unwrap();
    let _ = std::fs::create_dir("dir");
    scp.download("./dir", "test/a").unwrap();
    assert_file("./dir/a");
    assert_dir("./dir");

    // download a dir
    let scp = session.open_scp().unwrap();
    scp.download("./", "test").unwrap();
    assert_file("./test/a");
    assert_dir("./test");

    // download with a rename
    let scp = session.open_scp().unwrap();
    scp.download("./dir2", "test").unwrap();
    assert_file("./dir2/a");
    assert_dir("./dir2");

    // download with a rename #2
    let scp = session.open_scp().unwrap();
    scp.download("./dir2/", "test").unwrap();
    assert_file("./dir2/a");
    assert_dir("./dir2");

    session.close();
}

fn assert_file(filename: &str) {
    let file = std::path::Path::new(filename);

    println!("Assert file {}", filename);
    assert!(file.exists());

    std::fs::remove_file(file).unwrap();
}

fn assert_dir(dirname: &str) {
    let dir = std::path::Path::new(dirname);

    println!("Assert dir {}", dirname);
    assert!(dir.exists());

    std::fs::remove_dir(dir).unwrap();
}
