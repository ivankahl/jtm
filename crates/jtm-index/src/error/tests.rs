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

fn rejection(reason: Reason) -> Rejection {
    Rejection {
        variant: Some("temurin".to_owned()),
        version: "21.0.5+11".to_owned(),
        target: Target::Any,
        reason,
    }
}

fn not_confirmed() -> Reason {
    Reason::NotConfirmed {
        message: "one source only".to_owned(),
    }
}

fn disagree() -> Reason {
    Reason::SourcesDisagree {
        algorithm: HashAlgorithm::Sha256,
        claims: vec![
            ("a".to_owned(), "1".repeat(64)),
            ("b".to_owned(), "2".repeat(64)),
        ],
    }
}

#[test]
fn each_reason_maps_to_a_stable_code() {
    let code = |reason: Reason| reason.code().as_str();
    assert_eq!(code(disagree()), "E_HASH_MISMATCH");
    assert_eq!(
        code(Reason::ClaimMismatch {
            source_id: "a".to_owned(),
            origin: "x".to_owned(),
            algorithm: HashAlgorithm::Sha1,
            claimed: "1".to_owned(),
            computed: "2".to_owned(),
        }),
        "E_HASH_MISMATCH"
    );
    assert_eq!(
        code(Reason::SignatureInvalid {
            source_id: "a".to_owned(),
            url: "u".to_owned(),
            message: "m".to_owned(),
        }),
        "E_SIGNATURE_INVALID"
    );
    let size = |claimed, measured| Reason::SizeMismatch {
        source_id: "a".to_owned(),
        claimed,
        measured,
    };
    assert_eq!(code(size(10, 11)), "E_SIZE_EXCEEDED");
    assert_eq!(code(size(10, 9)), "E_HASH_MISMATCH");
    assert_eq!(
        code(Reason::TooLarge {
            url: "u".to_owned(),
            limit: 1
        }),
        "E_SIZE_EXCEEDED"
    );
    assert_eq!(code(not_confirmed()), "E_INDEX_INVALID");
    assert_eq!(
        code(Reason::AmbiguousPrimary { urls: Vec::new() }),
        "E_INDEX_INVALID"
    );
    assert_eq!(
        code(Reason::UnknownSource {
            source_id: "x".to_owned()
        }),
        "E_INDEX_INVALID"
    );
}

#[test]
fn a_run_with_several_rejections_reports_the_most_serious_code() {
    let error = Error::Rejected {
        rejections: vec![rejection(not_confirmed()), rejection(disagree())],
    };
    assert_eq!(error.code().as_str(), "E_HASH_MISMATCH");

    let error = Error::Rejected {
        rejections: vec![rejection(not_confirmed())],
    };
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");

    assert_eq!(
        Error::Io(std::io::Error::other("disk full"))
            .code()
            .as_str(),
        "E_IO"
    );
}

#[test]
fn the_message_names_each_entry_and_caps_a_long_list() {
    let one = Error::Rejected {
        rejections: vec![rejection(disagree())],
    }
    .to_string();
    assert!(one.starts_with("1 index entry refused"), "{one}");
    assert!(one.contains("temurin 21.0.5+11 (any)"), "{one}");
    assert!(one.contains("a says "), "{one}");
    assert!(one.contains("b says "), "{one}");

    let many = Error::Rejected {
        rejections: (0..25).map(|_| rejection(not_confirmed())).collect(),
    }
    .to_string();
    assert!(many.starts_with("25 index entries refused"), "{many}");
    assert!(many.contains("and 15 more"), "{many}");
}
