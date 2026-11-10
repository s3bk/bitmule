# bitmule-server

Signaling, relay and the link surfaces, in one process.

| surface | routes | what it does |
| --- | --- | --- |
| signaling | `/pow`, `/ws/create`, `/ws/join` | pairs a sender with receivers in a session room; sees handshake bytes only |
| relay | `/session/:sess/:receiver_id` | forwards fountain-coded frames when a direct path fails |
| shares | `/v1/pub/shares`, `/v1/pub/s/:sid/…` | stores ciphertext under a link's key: create, upload (resumable), commit, meta, session, ranges, delete |
| invites | `/v1/pub/i/:iid/…` | caps (bytes, files, one-time, TTL) for somebody else's upload, plus a granter token |
| inbox | `/v1/inbox`, `/v1/inbox/:uid` | the granter's list, content and delete, authorized by the granter token |

A credential is always a key that came in a link, or the granter token a person
was handed once. There are no accounts, no cookie and no server-side key that
decrypts stored bytes: rows carry hex `sha256(auth_key)`, and `auth_key` never
leaves the client.

## Layout

```
<data-dir>/shares/<sid>/meta.json          rows, state, counters
<data-dir>/shares/<sid>/<uid>.bin          ciphertext, as uploaded
<data-dir>/shares/<sid>/<uid>.part         an upload that has not finished
<data-dir>/invites/<iid>/meta.json         caps and received items
<data-dir>/invites/<iid>/uploads/<uid>.bin
<data-dir>/invites/<iid>/uploads/<uid>.part
<data-dir>/invites/by_granter/<hex>        inbox index: one invite id per line
<data-dir>/usage.tsv                       egress: day, kind, sid, bytes, responses
```

Metadata is JSON, written to a temp file and renamed. Payloads are streamed
both ways through one 256 KiB buffer (`IO_BUFFER`): an upload never sits in
memory, a download never reads the file whole, and a slow client applies
backpressure to the read instead of growing a buffer.

## Egress

Counted where the bytes leave — in the body stream, not from `Content-Length`
— so a viewer that closes a tab mid-range is billed for what it got. Sinks
accumulate a megabyte locally, then add to one of 32 sharded maps keyed by
(share, kind, day). The maps are drained into `usage.tsv` once an hour
(`--meter-flush-secs`); a failed write puts the rows back.

## Resuming

Both directions resume, and neither needs state of its own on the server.

**Upload.** A file's bytes land in `<uid>.part`, a name that does not change
between requests. The offset to resume from is that file's length, so there is
no journal to keep consistent: whatever the disk holds is the truth. A client
that lost a connection asks:

```
GET /v1/pub/s/<sid>/files/<uid>
  200 {"uid": …, "stored": 1200000, "total": 4000000, "uploaded": false}
  x-bm-offset: 1200000      x-bm-total: 4000000
```

and sends the rest, in whichever dialect it speaks — TUS (`Upload-Offset`,
`Upload-Length`), `Content-Range: bytes 1200000-…/4000000`, or `X-BM-Offset` /
`X-BM-Total`:

```
PUT /v1/pub/s/<sid>/files/<uid>
  Upload-Offset: 1200000
  → 204 x-bm-offset: 2800000        (more to come)
  → 201 x-bm-offset: 4000000        (complete, renamed into place)
  → 409 x-bm-offset: 1200000        (your offset was wrong; this is the true one)
```

Everything is checked against the file on disk while the body streams, and the
part is `sync_data`ed before its length is ever reported, so an offset that has
been handed out is an offset that survives a restart. A refused upload (over
the cap) drops its part: the cap will not change, so neither should the disk.
A restart at offset 0 replaces a finished file, which means "done" and "in
progress" are never true at once. Invites work the same way with the remaining
bytes as the cap; a part is not charged to `used_bytes` until it is complete,
so a resume does not pay for its own bytes twice.

**Download.** `Accept-Ranges: bytes`, honest 206s and a real `Content-Range`
were already what a resuming client needs. What was added is an `ETag` (size
and mtime of the stored file) and `If-Range`: a client that comes back with the
tag it was given gets `206` and the rest of the bytes; a client whose tag no
longer holds gets `200` and the whole file, rather than a splice of two
versions. `Cache-Control: private, max-age=0, must-revalidate` keeps links out
of shared caches without stopping a client from keeping its own partial copy.

## Hosts

`--bind` serves everything. `--link-bind` additionally serves the links-only
host: the viewer at `/`, the viewer's assets, `/healthz` and the key-addressed
`/v1/pub/…` routes. Everything else there answers with a page pointing at
`--main-host`.

The split is a second port, not a `Host` check: a TLS terminator rewrites
`Host` to the upstream it dialled (hyper's `set_host(true)`), so only the port
a vhost dials can tell `mul.li` from `bitmule.net`.

```
bitmule-server --bind 127.0.0.1:8443 --link-bind 127.0.0.1:8441 \
               --data-dir /var/lib/bitmule --web-dir /srv/bitmule/web \
               --main-host bitmule.net
```

nginx: `bitmule.net` -> 8443, `mul.li` -> 8441, both `proxy_pass`ed with the
usual WebSocket upgrade headers on `/ws/`.

## Security headers

Every response carries CSP (`script-src 'self' 'wasm-unsafe-eval'`,
`connect-src 'self'`, `frame-ancestors 'none'`), `Referrer-Policy:
no-referrer`, `nosniff`, `X-Frame-Options: DENY`, COOP and a permissions
policy. The viewer page holds the transfer secret, so no script from anywhere
else may run on it and no data may go anywhere but back to the origin.

## Tests

`tests/share_api.rs` drives the router the way the browser does: create, upload,
commit, whole-file and range reads, the 416 case, the egress row, key and
granter-token refusals, invite caps enforced mid-stream, and the gate covering
creation only. The resuming tests cut a body halfway through, read the offset
back, resume, and compare every byte; a wrong offset must be answered with the
true one, finishing twice must be harmless, and an `If-Range` that no longer
holds must yield the whole file instead of a spliced range.
