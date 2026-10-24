# Forks

Four crates are patched. Each fork is the exact upstream release tag plus one commit, so `git diff <upstream-tag>
<fork-tag>` is the whole change and can go upstream. The root `Cargo.toml` points `[patch.crates-io]` at the fork tags,
which covers transitive uses too (`sctp-proto` and `dimpl` come in through `str0m`). Nothing is built from `vendor/` any
more.

| Crate | Bitmule fork | From upstream release |
|---|---|---|
| `str0m` | https://github.com/s3bk/str0m `bitmule-v0.23.1` | https://github.com/algesten/str0m `0.23.1` |
| `sctp-proto` | https://github.com/s3bk/sctp-proto `bitmule-v0.10.4` | https://github.com/algesten/sctp-proto `0.10.4` |
| `tokio-uring` | https://github.com/s3bk/tokio-uring `bitmule-v0.5.0` | https://github.com/tokio-rs/tokio-uring `v0.5.0` |
| `dimpl` | https://github.com/s3bk/dimpl `bitmule-v0.7.6` | https://github.com/algesten/dimpl `0.7.6` |

The `str0m` fork is the upstream workspace, so `str0m-rust-crypto`, `str0m-proto` and `is` are built from the same tag.
`[patch]` is only honoured in the workspace root, so a project that depends on bitmule must repeat the four entries
(synthline does).

## Changing or upgrading a fork

The change is one commit on top of the release tag. To send it upstream: `git diff <upstream-tag> <bitmule-tag>` (or
`git format-patch`). To upgrade: check out the new upstream release tag, re-apply the change as one commit, push it as
`bitmule-v<version>`, and update the tag in `Cargo.toml`, here, and in the projects that depend on bitmule.

`patches/*.patch` holds the same changes as `diff`s against the crates.io packages, in the form they were applied before
the forks were rebuilt from the release tags. The git diff is canonical.

The old `s3bk/str0m` branch `bitmule-vendored` and the `s3bk/sctp-proto` / `s3bk/tokio-uring` branch `bitmule` are
obsolete: they sit on newer upstream `main` but contain older released code, so they silently revert upstream changes
(sctp-proto's `get_gap_ack_blocks` fix, many str0m tests). Do not point a build at them.

## Why each fork exists

### tokio-uring: bug fix

When a runtime is dropped, an in-flight op that was already abandoned (`Lifecycle::Ignored`) was replaced. That freed its
buffer, `msghdr` and address while the kernel still owned them, so the kernel wrote into freed memory. The fork keeps the
op's data alive until the cancel completes (`src/runtime/driver/mod.rs`). This is the only fork needed for correctness. It
looks like it still affects upstream, but that has not been checked, so it is worth sending upstream.

It also has a small `io::Error::other` to `io::Error::new` compatibility edit.

### str0m: throughput

- The data-channel send path takes a `Bytes`, so SCTP does not copy it.
- The receive path uses slab buffers, with merged or segmented delivery.
- `do_poll_output` loops over queued output instead of recursing, so a burst does not grow the stack.

### sctp-proto: throughput

- The payload queue uses Fx hashing instead of SipHash.
- `OwnedBytes` is a source whose chunks are slices of one `Bytes`, with no copying.

### dimpl: binary size

`str0m-rust-crypto` enables `dimpl`'s `rcgen` feature, which turned on `aws-lc-rs`, and `dimpl` fixed `rcgen`'s backend
to `aws_lc_rs`. That linked `aws-lc-sys` (about 270 KiB of code on arm64) next to `ring`, which `rustls` already needs.
The fork uses `rcgen`'s `ring` backend and `sha2` for the certificate fingerprint (`Cargo.toml`, `src/certificate.rs`).

## Decisions (2026-10-23)

Measured with the stock releases (`str0m` 0.23.1, `sctp-proto` 0.10.7) against the forks, 100 MB over `--webrtc`:

- Loopback: stock 33 MiB/s, fork 86 MiB/s. Over the WAN to sudfa (55 ms): both about 5.5 MiB/s. All four forks are kept.
- The fork's 1 MiB send buffer was reverted to upstream's 128 KiB: 40 MiB/s on loopback with 1 MiB, 86 with 128 KiB,
  equal on the WAN.
- `tokio-uring` upstream `master` (last commit July 2025) still has the use-after-free in `Driver::drop`; the patch is
  worth sending.
- `dimpl` stays for the Android size (about 270 KiB); upstream 0.8.0 still ties `rcgen` to aws-lc.
