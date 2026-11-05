# Forks

`[patch.crates-io]` in `Cargo.toml` points at three forks, by path — the code is in `vendor/` in this repo:

```toml
[patch.crates-io]
str0m = { path = "vendor/str0m" }
sctp-proto = { path = "vendor/sctp-proto" }
tokio-uring = { path = "vendor/tokio-uring" }
```

A `[patch]` section only applies in the workspace root, so a project that depends on bitmule must repeat these lines in its own `Cargo.toml`.

The path form is not cosmetic. The git branches cannot be used: `s3bk/str0m@bitmule-vendored`
(commit `1716db11`) depends on `bitmule-buf`, which is not published, so `cargo` fails with
`no matching package named bitmule-buf found`. Patching to `vendor/` is the same code, tracked
here, and needs no network.

The patched version must match the requirement, or the patch is silently unused: `str0m = "0.23"`
resolves to 0.23.0 on crates.io and does **not** match the 0.23.1 fork, so the build used upstream
str0m and lost `Delivery`, `write_bytes` and `set_channel_delivery` (fixed 2026-11-05:
`bitmule-client-native` requires `0.23.1`).

| Crate | Fork | Branch | Upstream | Vendored version |
|---|---|---|---|---|
| `str0m` | https://github.com/s3bk/str0m | `bitmule-vendored` | https://github.com/algesten/str0m | 0.23.1 |
| `sctp-proto` | https://github.com/s3bk/sctp-proto | `bitmule` | https://github.com/algesten/sctp-proto | 0.10.4 |
| `tokio-uring` | https://github.com/s3bk/tokio-uring | `bitmule` | https://github.com/tokio-rs/tokio-uring | 0.5.0 |

## Why each fork exists

### tokio-uring: bug fix

When a runtime is dropped, an in-flight op that was already abandoned (`Lifecycle::Ignored`) was replaced. That freed its buffer, `msghdr` and address while the kernel still owned them, so the kernel wrote into freed memory. The fork keeps the op's data alive until the cancel completes (`src/runtime/driver/mod.rs`, commit `25a6317`). This is the only fork needed for correctness. It looks like it still affects upstream, but that has not been checked, so it is worth sending upstream.

It also has a small `io::Error::other` to `io::Error::new` compatibility edit.

### str0m: throughput

- The send buffer across data-channel streams is 1 MiB instead of 128 KiB. 128 KiB throttles bulk transfer.
- The data-channel send path takes a `Bytes`, so SCTP does not copy it.
- The receive path uses slab buffers, with merged or segmented delivery.
- `BITMULE_SCTP_BUF` (KiB) overrides the buffer cap. It is temporary instrumentation, marked `TEMP-INSTR`.

### sctp-proto: throughput

- The payload queue uses Fx hashing instead of SipHash.
- The SACK delay can be configured.
- `OwnedBytes` is a source whose chunks are slices of one `Bytes`, with no copying.

## Known problem with the fork branches

The vendored code comes from crates.io releases, which are older than each fork's `main`. The branches sit on top of the newer `main` but contain the older code, so they silently revert upstream changes. Examples:

- sctp-proto's `get_gap_ack_blocks` fix.
- Many newer str0m tests and code.

They work as a snapshot of what bitmule builds and tests against. They are not a clean patch on top of upstream.

To fix this, rebuild each branch from the exact upstream commit the release was built from, and re-apply only the changes above. Only tokio-uring records that commit (`bf9906d`, in `.cargo_vcs_info.json`). For the other two, use the version tag. That also gives minimal diffs to send upstream.
