#[cfg(feature = "scp")]
mod test {
    use paste::paste;
    use ssh::{self, LocalSession};
    use std::env;

    fn remove_file(filename: &str) {
        let file = std::path::Path::new(filename);

        std::fs::remove_file(file).unwrap_or_else(|_| {
            std::process::Command::new("sudo")
                .arg("rm")
                .arg("-rf")
                .arg(filename)
                .output()
                .unwrap();
        });
    }

    fn assert_file_eq(file_1: &str, file_2: &str) {
        let md5_1 = std::process::Command::new("md5sum")
            .arg(file_1)
            .output()
            .expect("cannot calc the md5");
        let md5_2 = std::process::Command::new("md5sum")
            .arg(file_2)
            .output()
            .expect("cannot calc the md5");
        assert_eq!(md5_1.stdout[0..32], md5_2.stdout[0..32]);
    }

    fn remove_dir(dirname: &str) {
        let dir = std::path::Path::new(dirname);
        assert!(dir.exists());
        std::fs::remove_dir(dir).unwrap_or_else(|_| {
            std::process::Command::new("sudo")
                .arg("rm")
                .arg("-rf")
                .arg(dirname)
                .output()
                .unwrap();
        });
    }

    fn create_file(path: &str, cap: &str, peer: bool) {
        let _ = std::process::Command::new("fallocate")
            .arg("-l")
            .arg(cap)
            .arg(path)
            .output();
        let _ = std::process::Command::new("sudo")
            .arg("fallocate")
            .arg("-l")
            .arg(cap)
            .arg(path)
            .output();

        if peer {
            let _ = std::process::Command::new("chown")
                .arg(&get_username())
                .arg(path)
                .output();
            let _ = std::process::Command::new("sudo")
                .arg("chown")
                .arg(&get_username())
                .arg(path)
                .output();
        }
    }

    fn create_dir(path: &str, peer: bool) {
        std::fs::create_dir(path).unwrap_or_else(|_| {
            std::process::Command::new("sudo")
                .arg("mkdir")
                .arg(path)
                .output()
                .unwrap();
        });

        if peer {
            let _ = std::process::Command::new("chown")
                .arg(&get_username())
                .arg("-R")
                .arg(path)
                .output();
            let _ = std::process::Command::new("sudo")
                .arg("chown")
                .arg(&get_username())
                .arg("-R")
                .arg(path)
                .output();
        }
    }

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

    fn get_target_path(path: &str) -> String {
        format!("/home/{}/{}", get_username(), path)
    }

    fn create_session() -> LocalSession<std::net::TcpStream> {
        ssh::create_session()
            .username(&get_username())
            .private_key_path(get_pem_rsa())
            .connect(get_server())
            .unwrap()
            .run_local()
    }
    #[test]
    fn test_upload_file() {
        let mut session = create_session();

        create_file("test_file1", "2M", false);

        let scp = session.open_scp().unwrap();
        scp.upload("test_file1", "./").unwrap();
        assert_file_eq("test_file1", &get_target_path("test_file1"));
        remove_file(&get_target_path("test_file1"));
        remove_file("test_file1");

        session.close();
    }

    #[test]
    fn test_upload_file_rename() {
        let mut session = create_session();

        create_file("test_file2", "2M", false);

        let scp = session.open_scp().unwrap();
        scp.upload("test_file2", "./test_rename").unwrap();
        assert_file_eq("test_file2", &get_target_path("test_rename"));
        remove_file(&get_target_path("test_rename"));
        remove_file("test_file2");

        session.close();
    }

    #[test]
    fn test_upload_to_implicit_dir() {
        let mut session = create_session();

        create_dir(&get_target_path("test_dir1"), true);
        create_file("test_file3", "2M", false);

        let scp = session.open_scp().unwrap();
        scp.upload("test_file3", "./test_dir1").unwrap();
        assert_file_eq("test_file3", &get_target_path("test_dir1/test_file3"));
        remove_file(&get_target_path("test_dir1/test_file3"));
        remove_file("test_file3");
        remove_dir(&get_target_path("test_dir1"));

        session.close();
    }

    #[test]
    fn test_upload_dir() {
        let mut session = create_session();

        create_dir("test_dir2", false);

        let scp = session.open_scp().unwrap();
        scp.upload("test_dir2", "./").unwrap();
        remove_dir(&get_target_path("test_dir2"));
        remove_dir("test_dir2");

        session.close();
    }

    #[test]
    fn test_download_file() {
        let mut session = create_session();

        create_file(&get_target_path("test_file4"), "2M", true);

        let scp = session.open_scp().unwrap();
        scp.download("test_file4", "test_file4").unwrap();
        assert_file_eq("test_file4", &get_target_path("test_file4"));
        remove_file(&get_target_path("test_file4"));
        remove_file("test_file4");

        session.close();
    }

    #[test]
    fn test_download_file_rename() {
        let mut session = create_session();

        create_file(&get_target_path("test_file5"), "2M", true);

        let scp = session.open_scp().unwrap();
        scp.download("test_rename", "test_file5").unwrap();
        assert_file_eq("test_rename", &get_target_path("test_file5"));
        remove_file(&get_target_path("test_file5"));
        remove_file("test_rename");

        session.close();
    }

    #[test]
    fn test_download_to_implicit_dir() {
        let mut session = create_session();

        create_file(&get_target_path("test_file6"), "2M", true);
        create_dir("test_dir3", false);

        let scp = session.open_scp().unwrap();
        scp.download("test_dir3", "test_file6").unwrap();
        assert_file_eq("test_dir3/test_file6", &get_target_path("test_file6"));
        remove_file(&get_target_path("test_file6"));
        remove_file("test_dir3/test_file6");
        remove_dir("test_dir3");

        session.close();
    }

    #[test]
    fn test_download_dir() {
        let mut session = create_session();

        create_dir(&get_target_path("test_dir4"), true);

        let scp = session.open_scp().unwrap();
        scp.download("./", "test_dir4").unwrap();
        remove_dir("test_dir4");
        remove_dir(&get_target_path("test_dir4"));

        session.close();
    }
}
