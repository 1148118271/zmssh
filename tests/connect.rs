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
    env_getter!(passwd, "password");
    env_getter!(server, "127.0.0.1:22");
    env_getter!(pem_rsa, "./rsa_old");
    env_getter!(openssh_rsa, "./rsa_new");
    env_getter!(ed25519, "./ed25519");

    #[test]
    fn test_password() {
        let session = ssh::create_session()
            .username(&get_username())
            .password(&get_passwd())
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_password_backend() {
        let session = ssh::create_session()
            .username(&get_username())
            .password(&get_passwd())
            .connect(get_server())
            .unwrap()
            .run_backend();
        session.close();
    }

    #[test]
    fn test_rsa_old() {
        let session = ssh::create_session()
            .username(&get_username())
            .private_key_path(get_pem_rsa())
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_rsa_new() {
        let session = ssh::create_session()
            .username(&get_username())
            .private_key_path(get_openssh_rsa())
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_ed25519() {
        let session = ssh::create_session()
            .username(&get_username())
            .private_key_path(get_ed25519())
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }

    #[test]
    fn test_pubkey_fallback() {
        let session = ssh::create_session()
            .username(&get_username())
            .password(&get_passwd())
            .private_key_path("")
            .connect(get_server())
            .unwrap()
            .run_local();
        session.close();
    }
}
