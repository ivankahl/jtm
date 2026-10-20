use super::*;

#[test]
fn network_settings_reach_the_http_client() {
    let mut settings = Config::load(&ConfigInputs {
        user: None,
        project: None,
        env: &|_| None,
        flags: &[],
    })
    .unwrap()
    .settings;
    settings.security.allow_http_mirrors = true;
    settings.network.proxy = Some("http://proxy.example:8080".to_owned());
    settings.network.extra_ca_file = Some(PathBuf::from("/etc/corp-ca.pem"));
    let options = client_options(&settings);
    assert!(options.allow_http);
    assert_eq!(options.proxy.as_deref(), Some("http://proxy.example:8080"));
    assert_eq!(
        options.extra_ca_file.as_deref(),
        Some(Path::new("/etc/corp-ca.pem"))
    );
}
