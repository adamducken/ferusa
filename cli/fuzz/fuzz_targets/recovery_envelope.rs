#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cheap parsing only: arbitrary inputs never invoke Argon2 in the fuzzer.
    if ferusa_core::recovery::validate_recovery_envelope(data).is_ok() {
        assert_eq!(data.len(), ferusa_core::recovery::RECOVERY_FILE_LEN);
    }
});
