# Pricing Sheet

## Platform Pricing

| Product | Price | Model |
|---|---|---|
| Desktop app | Free | Open source |
| CLI | Free | Open source |
| Web app | Free | No sign-up required for direct (P2P) sharing |
| Android app | 5€ | One-time purchase |
| iOS app | 10€ | One-time purchase |

Pro services (below) are usable identically from every platform above.

---

## Pro Services Subscription

Two tiers. Identity verification (payment + email, at minimum) is mandatory for both — this is core to abuse mitigation for the hosted services and is not optional or trial-free.

| | **Basic** | **Extended** |
|---|---|---|
| Price | 4€/month | 10€/month |
| Storage | 100GB | 500GB |
| Bandwidth | 500GB/month | 2TB/month |

**Auto-downgrade rule:** if actual usage in a billing period stays within Basic's limits (≤100GB storage, ≤500GB bandwidth) despite being subscribed at Extended, the customer is billed at the Basic price for that period instead.

**Basic-tier refund:** if usage stays under 20GB storage (peak, at any point in the period) *and* 100GB bandwidth (summed) — i.e. under 20% of Basic's caps — the customer can cancel and receive a full refund for that period. This applies to whichever tier the customer was actually *billed* at (post auto-downgrade), not necessarily the tier they originally selected. This is trial insurance, not a recurring monthly rebate — it only pays out on cancellation.

---

## Overage (flat, metered — no pre-purchased packs)

Once a subscriber exceeds their tier's included storage or bandwidth, usage beyond the limit is billed automatically at period close, at a flat per-GB rate. No blocks to buy, nothing to roll over or refund — you're billed for exactly what you used.

| Resource | Rate |
|---|---|
| Storage overage | 0.006€/GB·month |
| Bandwidth overage | 0.0025€/GB |

Recommended: trigger a usage alert (e.g. at 2x baseline) so overage billing doesn't come as a surprise, since there's no longer a pre-purchased cap to make the ceiling visible in advance.

---

## Cost Basis & Margins

| Resource | Internal cost | Notes |
|---|---|---|
| Storage (Hetzner Storage Box, BX41) | 2€/TB·month (0.002€/GB) | 20TB capacity per box |
| Bandwidth | **€0 marginal cost** | Storage Box traffic is unlimited and free of cost |
| App/cache server | $60/month (2TB SSD) | Fixed cost, not per-user. Functions as a buffering/caching layer in front of the Storage Box |

**Storage margins:**

| | Cost | Price | Margin |
|---|---|---|---|
| Basic (100GB) | 0.20€ | included in 4€ | — |
| Extended (500GB) | 1.00€ | included in 10€ | — |
| Storage overage | 0.002€/GB | 0.006€/GB | ~67% |

**Bandwidth margins:** effectively unbounded on a per-GB basis (true infra cost is €0), so bandwidth pricing/overage functions as pure margin and a soft throttle rather than cost recovery.

### Infrastructure capacity notes (BX41)
- Sequential write: 62.4 MB/s (~500 Mbps) → theoretical max ~161 TB/month if fully saturated
- Sequential read: 544 MB/s (~4.3 Gbps) → theoretical max ~1.4 PB/month if fully saturated
- 10 concurrent connections per box — the practical bottleneck for burst load (e.g. a hosted inbox receiving many simultaneous uploads, or a shared-cap download link fanning out to many recipients at once), not raw throughput or cost
- Scaling path: add additional Storage Boxes and shard subscribers behind the app-server caching layer as volume grows; cost scales linearly (2€/TB per additional box, unlimited traffic on each)

---

## Open items / assumptions to confirm before launch
- Confirm current Hetzner Storage Box terms haven't changed since this sheet was built (traffic policy, per-box pricing).
- Decide the usage-alert threshold and delivery mechanism for overage billing.
- Confirm identity verification bar (payment + email vs. + phone) based on early abuse signal once live.
