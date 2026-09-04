# Feature Overview

## Platforms

| Platform | Cost | Notes |
|---|---|---|
| **Desktop app** | Free, open source | Full-featured |
| **CLI** | Free, open source | Full-featured, scriptable |
| **Web app** | Free | Full P2P sharing; hosted pro services also usable here. No background sync or auto-upload (browser limitation) |
| **Android / iOS app** | Small one-time fee | Native convenience: share-sheet integration, background sync, camera roll access, push notifications. Same functionality as the web app, packaged for people who don't want to open a browser tab or move files out of a downloads folder |

Pro services (hosted uploads and hosted inbox) work identically across **all** platforms — desktop, CLI, web, and mobile.

---

## Privacy & Security

- **End-to-end encryption, two layers.** Files are compressed, padded, and encrypted before they ever leave your device.
- **Verified integrity** A shared link is tied to one file. It can't be modified later by anbody.
- **The server never sees your key.** For direct P2P shares, the decryption key is derived from a piece of the link itself that never gets sent to any server — only someone with the full link can decrypt.
- **Optional password protection.** Add a password for an extra layer on top of the link-based key. Since you're typically sharing with people you already know, if the wrong password is entered, just ask the sender to resend it — downloads start immediately rather than waiting on password verification, so you're not stuck waiting on a large transfer twice.
- **Automatic metadata stripping.** Identifying metadata (e.g. photo EXIF data) is removed before encryption.
- **What we deliberately don't do:** no server-side virus scanning, no link previews/thumbnails, no watermarking, no content-based audit trails. All of these would require us to see inside your files — and we can't, by design.

---

## Direct Sharing (P2P)

- Share files and folders instantly via a link — the recipient's browser or app starts downloading automatically.
- No account needed to send or receive a direct share.
- Works across desktop, CLI, and web.

---

## Pro Services

Hosted uploads and hosted inbox require a subscription, which links the service to a verified identity. This isn't optional — it's what lets us keep the service free of the spam and abuse that has taken down similar "anonymous link" tools in the past, without ever inspecting the contents of your files.

### Hosted Uploads
Upload a file once and get a persistent link that works any time — your device doesn't need to stay online.

- Generate **unique links** per recipient (each individually revocable, without affecting anyone else's access).
- Generate a **shared link with a download cap** (e.g., "first 10 downloads") for posting somewhere public or semi-public.
- **Mix both on the same upload** — a few named links for specific people, plus a capped shared link for a wider group, all pointing at one uploaded file.
- **Default 7-day expiry**, adjustable account-wide or overridden per upload.
- A single-use link is only consumed once the download **completes successfully** — a dropped connection won't burn a link for nothing.

### Hosted Inbox
Let anyone send you files without your device being online — delivered securely to you and only you.

- **Generate one-time upload links** via the app, CLI, or REST API — share one with a specific person for a single delivery.
- **Grant standing upload access** to registered contacts, with configurable storage and file-count limits, for people who send you files regularly.
- Uploaded files are encrypted directly to your identity — only your private key can open them, and it never touches our servers.
- **CLI and API access** make bulk workflows possible: generate a batch of one-time links (e.g., for an event, a class, or a list of vendors), or trigger a webhook when a new file arrives to plug into your own automation.

---

## Trust & Contacts

Your identity is backed by a cryptographic key pair, similar in spirit to how SSH handles trusted hosts:

- **Add a contact directly** by their public key or its fingerprint — the natural flow when an inbox link already carries that information.
- **Import a contact by username**, with a fingerprint confirmation step for ongoing relationships you want to pin long-term.
- **Multi-device key sync (optional).** Choose to sync your private key across your own devices so you can access hosted inbox content anywhere, or keep it on a single device for maximum control.
- **Key rotation, done safely.** If you rotate your key, your old key signs the new one — everyone who already trusts you updates automatically, with no action needed on their end, and links generated before the rotation keep working until they're fully used or expired. Rotation without your old key isn't possible, by design — it's what keeps the trust chain from being spoofed.

---

## Pricing

- **Desktop, CLI:** Free forever.
- **Web app:** Free forever.
- **Mobile app (Android/iOS):** One-time fee (a few dollars), covering development and app store costs — not a subscription.
- **Pro Services subscription:** Single plan covering both Hosted Uploads and Hosted Inbox, with generous default storage and bandwidth, usable from every platform.
  - **Try it risk-free:** if you use less than 20% of both your storage and bandwidth allowance in your first billing period, you're automatically refunded — no need to ask.
- **Need more?** Additional storage and bandwidth are available as add-on packs, or as one-time bandwidth bursts for occasional large sends — bought separately from the subscription, so you only pay for what you actually need more of.

---

*Have a feature request or found something that doesn't work as described? We'd love to hear it.*
