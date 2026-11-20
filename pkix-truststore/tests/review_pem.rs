//! Review regression tests for pkix-truststore PEM loading.
//! Uses the existing tests/fixtures/cert1.pem (no new fixtures).

use pkix_truststore::from_pem;

const CERT1_PEM_PATH: &str = "tests/fixtures/cert1.pem";

/// `from_pem` rustdoc: "Accepts ... Trailing whitespace (spaces, tabs,
/// blank lines) after the last `-----END CERTIFICATE-----`." RFC 7468 §2
/// also permits trailing whitespace. x509-cert 0.2 `load_pem_chain`
/// only strips trailing CR/LF, so a space or tab is rejected.
#[test]
fn trailing_spaces_and_tabs_after_last_end_load() {
    let cert = std::fs::read_to_string(CERT1_PEM_PATH).unwrap();
    for tail in [" ", "  \n", "\t", "\n\t \n", "-----END CERTIFICATE----- \n"] {
        let input = if tail.starts_with("-----END") {
            // trailing blank on the END line itself
            cert.trim_end().to_owned() + " \n"
        } else {
            format!("{cert}{tail}")
        };
        let r = from_pem(input.as_bytes());
        assert!(
            matches!(&r, Ok(v) if v.len() == 1),
            "tail {tail:?}: expected 1 anchor, got {r:?}"
        );
    }
}
