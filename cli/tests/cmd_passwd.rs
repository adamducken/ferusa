mod common;

use common::{sample_entry, vault_with_entries, TestContext};
use predicates::str::contains;

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_passwd_success() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "old_pass",
        vault_with_entries(vec![sample_entry("GitHub", Some("alice"), "secret123")]),
    );

    ctx.cmd(&["passwd"])
        .write_stdin("old_pass\nnew_pass_long\nnew_pass_long\n")
        .assert()
        .success()
        .stdout(contains("CHANGE_PASSWORD"));

    assert!(ctx.read_vault("old_pass").is_err());

    let vault = ctx
        .read_vault("new_pass_long")
        .expect("decrypt vault with new password");
    assert_eq!(vault.entries.len(), 1);
    assert_eq!(vault.entries[0].title, "GitHub");
    assert!(
        !ctx.vault_salt().exists(),
        "password change should remove stale legacy vault.salt"
    );
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_passwd_does_not_rewrite_non_file_legacy_salt_path() {
    let ctx = TestContext::new();
    ctx.init_vault("old_pass");
    std::fs::remove_file(ctx.vault_salt()).expect("remove legacy vault.salt");
    std::fs::create_dir(ctx.vault_salt()).expect("replace legacy vault.salt with directory");

    ctx.cmd(&["passwd"])
        .write_stdin("old_pass\nnew_pass_long\nnew_pass_long\n")
        .assert()
        .success();

    assert!(ctx.read_vault("old_pass").is_err());
    assert!(ctx.read_vault("new_pass_long").is_ok());
    assert!(
        ctx.vault_salt().is_dir(),
        "non-file legacy vault.salt path should not be overwritten"
    );
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_passwd_rejects_invalid_pairing_and_preserves_files() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "old_pass",
        vault_with_entries(vec![sample_entry("GitHub", Some("alice"), "secret123")]),
    );
    std::fs::write(ctx.phone_id(), "invalid-phone-id").expect("write phone.id");
    std::fs::write(ctx.hmac_key(), [0u8; 32]).expect("write hmac.key");
    let pairing = b"{}";
    std::fs::write(ctx.pairing_state(), pairing).expect("write pairing.json");

    ctx.cmd(&["passwd"])
        .write_stdin("old_pass\nnew_pass_long\nnew_pass_long\n")
        .assert()
        .failure()
        .stdout(contains("invalid pairing state"));

    assert!(ctx.phone_id().exists(), "phone.id should be preserved");
    assert!(ctx.hmac_key().exists(), "hmac.key should be preserved");
    assert!(
        ctx.pairing_state().exists(),
        "pairing.json should be preserved"
    );
    assert_eq!(std::fs::read(ctx.pairing_state()).unwrap(), pairing);
    assert!(ctx.read_vault("old_pass").is_ok());
    assert!(ctx.read_vault("new_pass_long").is_err());
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_passwd_fails_when_unpaired() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "old_pass",
        vault_with_entries(vec![sample_entry("GitHub", Some("alice"), "secret123")]),
    );

    ctx.cmd(&["passwd"])
        .write_stdin("old_pass\nnew_pass_long\nnew_pass_long\n")
        .assert()
        .failure()
        .stdout(contains("2FA unavailable"));

    assert!(ctx.read_vault("old_pass").is_ok());
    assert!(ctx.read_vault("new_pass_long").is_err());
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_failed_passwd_does_not_delete_pairing_files() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "old_pass",
        vault_with_entries(vec![sample_entry("GitHub", Some("alice"), "secret123")]),
    );
    std::fs::write(ctx.hmac_key(), [0u8; 32]).expect("write hmac.key");

    ctx.cmd(&["passwd"])
        .write_stdin("old_pass\nnew_pass_long\nnew_pass_long\n")
        .assert()
        .failure();

    assert!(
        ctx.hmac_key().exists(),
        "hmac.key should remain after failed passwd"
    );
    assert!(ctx.read_vault("old_pass").is_ok());
    assert!(ctx.read_vault("new_pass_long").is_err());
}
