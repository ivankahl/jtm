use super::*;

const KEY: &str = "RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB";

#[test]
fn parses_a_minisign_public_key() {
    let key = PublicKey::parse(&format!("  {KEY}\n")).unwrap();
    assert_eq!(key.as_str(), KEY);
    assert_eq!(key.to_string(), KEY);
    assert_eq!(key.id().to_string().len(), 16);
    assert_eq!(key, KEY.parse::<PublicKey>().unwrap());
}

#[test]
fn rejects_anything_else() {
    for bad in [
        "",
        "RW",
        "not base64!",
        // Valid base64 of the wrong length.
        "RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PBAAAA",
        // Right length, wrong algorithm bytes.
        "AAAA5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB",
        // Padding in the middle.
        "RW==5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB",
    ] {
        assert!(PublicKey::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn scopes_name_valid_plugins() {
    let scope = Scope::plugins(["java", "acme/flyway"]).unwrap();
    assert!(scope.covers("java"));
    assert!(scope.covers("acme/flyway"));
    assert!(!scope.covers("maven"));
    assert!(Scope::plugins(["Java"]).is_err());
    assert!(Scope::plugins(["*"]).is_err());
    assert!(Scope::plugins(Vec::<String>::new()).is_err());
}
