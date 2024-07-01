mod tests {
    use paste::paste;

    use std::env;

    macro_rules! env_getter {
        ($field:ident, $default: expr) => {
            paste! {
                pub fn [<get_ $field>]() -> String {
                    env::var("SSH_RS_TEST_".to_owned() + stringify!([<$field:upper>])).unwrap_or($default.to_owned())
                }
            }
        };
    }
    env_getter!(username, "ubuntu");
    env_getter!(server, "127.0.0.1:22");
    env_getter!(pem_rsa, "./rsa_old");

    #[test]
    fn test_exec() {
        let mut session = ssh::create_session()
            .username(&get_username())
            .private_key_path(get_pem_rsa())
            .connect(get_server())
            .unwrap()
            .run_local();
        let exec = session.open_exec().unwrap();
        let vec: Vec<u8> = exec.send_command("ls -all").unwrap();
        println!("{}", String::from_utf8(vec).unwrap());
        // Close session.
        session.close();
    }

    #[test]
    fn test_exec_backend() {
        let mut session = ssh::create_session()
            .username(&get_username())
            .private_key_path(get_pem_rsa())
            .connect(get_server())
            .unwrap()
            .run_backend();
        let mut exec = session.open_exec().unwrap();

        const CMD: &str = "ls -lah";

        // send the command to server
        println!("Send command {}", CMD);
        exec.send_command(CMD).unwrap();

        // process other data
        println!("Do someother thing");

        // get command result
        let vec: Vec<u8> = exec.get_result().unwrap();
        println!("{}", String::from_utf8(vec).unwrap());

        // Close session.
        session.close();
    }
}
