mod common;

use common::{sample_entry_full, vault_with_entries, TestContext};
#[cfg(feature = "dev-2fa-stub")]
use ferusa_core::crypto::{combine_vault_key, derive_keys, encrypt_vault, new_salt};
#[cfg(feature = "dev-2fa-stub")]
use ferusa_core::types::Vault;
#[cfg(feature = "dev-2fa-stub")]
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_get_success() {
    let ctx = TestContext::new();
    ctx.configure_fake_clipboard();

    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "secret123",
            Some("https://github.com"),
            Some("personal"),
            vec!["work", "social"],
        )]),
    );

    ctx.cmd(&["get", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .success()
        .stdout(
            contains("username:")
                .and(contains("alice"))
                .and(contains(
                    "password copied; automatic clipboard clearing is disabled",
                ))
                .and(contains("secret123").not()),
        );
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_get_dev_stub_requires_explicit_env() {
    let ctx = TestContext::new();
    ctx.configure_fake_clipboard();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "secret123",
            None,
            None,
            vec![],
        )]),
    );

    let mut cmd = ctx.cmd(&["get", "GitHub"]);
    cmd.env_remove("FERUSA_ALLOW_DEV_2FA_STUB");
    cmd.write_stdin("master_pw\n")
        .assert()
        .failure()
        .stdout(contains("FERUSA_ALLOW_DEV_2FA_STUB=1"));
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_get_fails_when_unpaired() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "secret123",
            None,
            None,
            vec![],
        )]),
    );

    ctx.cmd(&["get", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .failure()
        .stdout(contains("2FA unavailable"));
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_get_rejects_dev_stub_vault_marker() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "secret123",
            None,
            None,
            vec![],
        )]),
    );
    std::fs::write(
        ctx.dev_2fa_stub_marker(),
        br#"{
  "version": 1,
  "warning": "This vault was created with the deterministic dev 2FA stub and is not production-compatible."
}"#,
    )
    .expect("write dev marker");

    ctx.cmd(&["get", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .failure()
        .stdout(contains("not production-compatible"));
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_list_success() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![
            sample_entry_full(
                "GitHub",
                Some("alice"),
                "secret123",
                Some("https://github.com"),
                None,
                vec![],
            ),
            sample_entry_full(
                "AWS",
                Some("root"),
                "aws-pass",
                Some("https://aws.amazon.com"),
                None,
                vec![],
            ),
        ]),
    );

    ctx.cmd(&["list"])
        .write_stdin("master_pw\n")
        .assert()
        .success()
        .stdout(
            contains("GitHub")
                .and(contains("AWS"))
                .and(contains("2 entries.")),
        );
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_list_uses_salt_embedded_in_vault_enc() {
    let ctx = TestContext::new();
    std::fs::create_dir_all(ctx.data_dir()).expect("create data dir");

    let stale_salt = new_salt();
    let real_salt = new_salt();
    let keys = derive_keys(b"master_pw", &real_salt).expect("derive keys");
    let vault_key = combine_vault_key(&keys.local_secret, &crate::common::TEST_PHONE_SHARE)
        .expect("combine vault key");
    let vault = Vault::default();
    let plaintext = serde_json::to_vec(&vault).expect("serialize vault");
    let blob = encrypt_vault(&vault_key, real_salt, &plaintext).expect("encrypt vault");

    std::fs::write(ctx.vault_salt(), stale_salt).expect("write stale vault.salt");
    std::fs::write(ctx.vault_enc(), blob.to_bytes()).expect("write vault.enc");
    std::fs::write(
        ctx.dev_2fa_stub_marker(),
        br#"{
  "version": 1,
  "warning": "This vault was created with the deterministic dev 2FA stub and is not production-compatible."
}"#,
    )
    .expect("write dev marker");

    ctx.cmd(&["list"])
        .write_stdin("master_pw\n")
        .assert()
        .success()
        .stdout(contains("vault is empty"));
}
