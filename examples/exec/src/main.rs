
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
    let exec = session.open_exec().unwrap();
    let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
    println!("{}", String::from_utf8(vec).unwrap());

    let mut exec = session.open_exec().unwrap();
    exec.exec_command("no_command").unwrap();
    let vec = exec.get_output().unwrap();
    println!("output: {}", String::from_utf8(vec).unwrap());
    println!("exit status: {}", exec.exit_status().unwrap());
    println!("terminated msg: {}", exec.terminate_msg().unwrap());
    let _ = exec.close();

    // Close session.
    session.close();
}
