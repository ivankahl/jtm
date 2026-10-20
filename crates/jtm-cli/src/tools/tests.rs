use std::collections::BTreeMap;

use jtm_core::session::AvailableItem;

use super::*;

fn item(variant: &str, version: &str) -> AvailableItem {
    AvailableItem {
        variant: variant.to_owned(),
        version: version.to_owned(),
        tags: Vec::new(),
        installed: false,
    }
}

#[test]
fn aliases_label_only_rows_of_the_variant_they_resolve_in() {
    let data = AvailableData {
        available: Available {
            tool: "demo".to_owned(),
            platform: "linux-x64".to_owned(),
            versions: vec![item("main", "21.0.5"), item("other", "21.0.5")],
            aliases: BTreeMap::from([("lts".to_owned(), "21.0.5".to_owned())]),
            alias_variant: "main".to_owned(),
        },
    };
    let mut out = Vec::new();
    data.render_human(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "main:21.0.5  (lts)\nother:21.0.5\n"
    );
}
