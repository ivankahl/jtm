#![allow(clippy::unwrap_used)]

use jtm_core::Platform;

/// CI sets `JTM_EXPECTED_PLATFORM` per runner, so every runner proves detection is correct.
/// Locally, without the variable, detection only has to succeed.
#[test]
fn detected_platform_matches_the_runner() {
    let detected = Platform::detect().unwrap();
    if let Some(expected) = std::env::var("JTM_EXPECTED_PLATFORM")
        .ok()
        .filter(|v| !v.is_empty())
    {
        assert_eq!(detected.as_str(), expected);
    }
}
