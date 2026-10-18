# bitmule-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) that lets agents send
and receive files over bitmule: end-to-end encrypted, direct when possible,
through the relay otherwise. Built on the `bitmule::Client` API.

| tool | what it does |
| --- | --- |
| `bitmule_send` | `paths` (files or folders), optional `name`, `server`, `mode` (`auto`/`relay`/`webrtc`). Returns the `share_url` and a `transfer_id` at once; the send continues in the background until the receivers that connected are done. Several paths or a folder go as one bundle the receiver unpacks. |
| `bitmule_send_status` | `transfer_id` -> `sending` / `done` / `failed`, bytes the receiver has, error. |
| `bitmule_receive` | `url`, optional `dest`, `server`, `mode`. Waits until the transfer is complete, returns the files (`name`, `path`, `bytes`). |

Environment: `BITMULE_SERVER` (relay; default `https://bitmule.qdat.net`),
`BITMULE_DOWNLOADS` (where `bitmule_receive` saves when `dest` is not given;
default the working directory).

```bash
cargo install --path crates/bitmule-mcp
claude mcp add bitmule -- bitmule-mcp          # Claude Code
```

or in an `.mcp.json`:

```json
{ "mcpServers": { "bitmule": { "command": "bitmule-mcp", "env": { "BITMULE_DOWNLOADS": "/home/me/downloads" } } } }
```

A sending agent has to keep the process running while the receiver fetches
(the data is read from the sender's disk); `bitmule_send_status` says when it
is done.
