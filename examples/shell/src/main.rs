use ssh::{self, LocalShell, SshError};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use std::time::Duration;

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
        .timeout(Some(Duration::from_millis(1000)))
        .private_key_path("./id_rsa")
        .connect("127.0.0.1:22")
        .unwrap()
        .run_local();
    // Usage 1
    let mut shell = session.open_shell().unwrap();
    run_shell(&mut shell);

    // Close channel.
    shell.close().unwrap();
    // Close session.
    session.close();
}

fn run_shell(shell: &mut LocalShell<std::net::TcpStream>) {
    let out = shell.read().unwrap();
    print!("{}", String::from_utf8(out).unwrap());

    shell.write(b"ls -lah\n").unwrap();

    loop {
        match shell.read() {
            Ok(out) => print!("{}", String::from_utf8(out).unwrap()),
            Err(e) => {
                if let SshError::TimeoutError = e {
                    break;
                } else {
                    panic!("{}", e.to_string())
                }
            }
        }
    }

    let _ = shell.close();
    println!("exit status: {}", shell.exit_status().unwrap());
    println!("terminated msg: {}", shell.terminate_msg().unwrap());
}
