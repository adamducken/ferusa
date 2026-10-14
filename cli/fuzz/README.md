# CLI Fuzzing

`cargo-fuzz` targets for CLI outer-world boundaries.

Normal `cargo test` runs the fast property/regression tests under
`cli/src/tests/properties` and `cli/tests/properties`. This directory is only
for long-running, coverage-guided fuzzing.

Run from `cli/`:

```sh
cargo fuzz list
cargo fuzz run clipboard_command
cargo fuzz run cli_args
cargo fuzz run pairing_files
cargo fuzz run private_file
cargo fuzz run vault_blob
cargo fuzz run wire_message
cargo fuzz run recovery_envelope
cargo fuzz coverage wire_message
```

Targets are bounded and side-effect scoped:

- `clipboard_command`: parses configured clipboard commands only; never spawns.
- `cli_args`: fuzzes clap argument parsing.
- `pairing_files`: fuzzes atomic `pairing.json`, pending markers, and legacy split-file states.
- `private_file`: writes bounded fuzz data to a temp private file.
- `vault_blob`: fuzzes encrypted vault blob and vault JSON parsing.
- `wire_message`: fuzzes length-prefixed Ferusa network messages.
- `recovery_envelope`: checks bounded recovery envelope headers without running Argon2.
