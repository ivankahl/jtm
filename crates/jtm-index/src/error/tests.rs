use super::*;

fn fetch(error: jtm_fetch::Error) -> Error {
    Error::Fetch {
        source_id: "s".to_owned(),
        error,
    }
}

#[test]
fn every_failure_has_a_stable_code() {
    let status = fetch(jtm_fetch::Error::Status {
        url: "u".to_owned(),
        status: 500,
    });
    assert_eq!(status.code().as_str(), "E_NETWORK");

    let too_large = fetch(jtm_fetch::Error::TooLarge {
        url: "u".to_owned(),
        limit: 1,
    });
    assert_eq!(too_large.code().as_str(), "E_SIZE_EXCEEDED");

    let scheme = fetch(jtm_fetch::Error::Scheme {
        url: "u".to_owned(),
        reason: "r".to_owned(),
    });
    assert_eq!(scheme.code().as_str(), "E_USAGE");

    let missing = Error::Missing {
        source_id: "s".to_owned(),
        url: "u".to_owned(),
    };
    assert_eq!(missing.code().as_str(), "E_NETWORK");

    let sources = Error::Sources {
        file: "sources.toml".to_owned(),
        message: "m".to_owned(),
    };
    assert_eq!(sources.code().as_str(), "E_PLUGIN_INVALID");

    let response = Error::response("s", "u", "m");
    assert_eq!(response.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn messages_name_the_source() {
    let message = Error::response("adoptium-api", "https://x.test/a", "not an array").to_string();
    assert!(message.contains("adoptium-api"), "{message}");
    assert!(message.contains("https://x.test/a"), "{message}");
}
