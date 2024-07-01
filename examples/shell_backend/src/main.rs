use ssh::{self, ShellBrocker};
use std::thread::sleep;
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

    let mut session = ssh::create_session()
        .username("ubuntu")
        .password("password")
        .private_key_path("./id_rsa")
        .connect("127.0.0.1:22")
        .unwrap()
        .run_backend();
    // Usage 1
    let mut shell = session.open_shell().unwrap();
    run_shell(&mut shell);

    // Close channel.
    shell.close().unwrap();
    sleep(Duration::from_secs(2));
    println!("exit status: {}", shell.exit_status().unwrap());
    println!("terminated msg: {}", shell.terminate_msg().unwrap());
    // Close session.
    session.close();
}

fn run_shell(shell: &mut ShellBrocker) {
    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());

    shell.write(b"ls -all\n").unwrap();

    sleep(Duration::from_secs(2));
    let vec = shell.read().unwrap();
    println!("{}", String::from_utf8(vec).unwrap());
}
