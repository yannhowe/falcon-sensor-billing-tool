# Reconcile to billing, show per-tag consumption, justify FCSC

*Design note, 2026-10-01. It builds on `docs/how-chargeback-works.md` (the bug map) and `docs/oci-event-validation.md` (which OCI event to count). It describes the target design, not current behavior. No code is changed by this doc.*

## Summary

- The Sensor Usage API is the number that gets billed. The tool treats it as the authoritative total per CID, and never computes a competing total.
- The tool's per-tag view is showback, not allocation. Each tag shows the licenses that tag consumes. A host with two tags counts fully under both, so the per-tag numbers deliberately sum to more than the CID total.
- Consumption is measured in sensor-hours, the same unit billing measures in. That is what makes ephemeral workloads reconcile.
- FCSC is determined from `OciContainerInfo`, which is KAC-independent and catches standalone Docker hosts. The same event carries the image and engine identity that justifies the FCSC classification per host.
- `falcon_search_kubernetes_containers` is demoted to K8s-only enrichment. It adds namespace, pod, and registry where KAC is deployed. It is evidence, never the count.

## The three asks

1. **Make the tool match billing.** The Sensor Usage API is what CrowdStrike bills against. The tool's per-CID total must equal it, not diverge from it.
2. **Show cost per tag.** Teams are charged back by their `SensorGroupingTag`. Each tag shows how many licenses it consumes. This is showback, so a shared host counts fully under every tag that owns it, and the tag totals add up to more than the CID total on purpose.
3. **Justify the FCSC.** A team whose host is billed as a container host should see which containers, images, and engines ran on it, so the classification is legible rather than asserted.

## Design

### Layer 1: the billing API is the authoritative CID total

Per CID, per SKU, the authoritative number is `SensorUsage.get_hourly_usage` with `period:'28'` and `selected_cids:'<own cid>'`. Each row is already a rolling 28-day average of unique active sensors of that SKU. Call it `B[sku]`, for example `containers = 72.88` on talon_1.

The tool stores `B[sku]` per CID per collection date. This is the CID's billed number. It is what the `billing_averages` table was meant to hold and never did (`how-chargeback-works.md`, path 2 table). It is reported as the CID total, and the per-tag view sits beside it, not inside it.

Without `selected_cids` the API returns a far larger scope than the tenant (~114k servers against 378 hosts on talon_1). The CID total is only valid with `selected_cids` set.

### Layer 2: per-tag consumption is showback

The tool records, per hour, per tag, per SKU, the count of unique sensors carrying that tag and active in that hour (`hourly_tag_counts`). Each tag's consumption is its own 28-day average of that count, per SKU. It is computed directly from the tag's own hours, not carved out of the CID total.

```
Consumed[tag,sku] = ( sum over hours of unique sensors with tag and sku active that hour ) / N
```

A host that carries two grouping tags counts fully under each. So `sum over tags of Consumed[tag,sku]` is greater than or equal to `B[sku]`, and exceeds it whenever hosts carry more than one tag. This is the intended behavior. The number tells a team "your tag consumes N licenses," which is the full weight of the hosts it owns, shared or not. It is not a division of the invoice.

Because per-tag is showback, the multi-tag problem disappears. There is no split rule and no attribution-once constraint. The current `hourly_tag_counts` behavior, which counts a multi-tag sensor once per tag, is correct for this design rather than a defect.

The unit is still sensor-hours, so ephemerality is still absorbed (see below). Only the normalization is dropped. Each tag is measured on its own, and the CID total from Layer 1 remains the single billed number.

## FCSC determination and evidence

### Count: OciContainerInfo, extended to catch older-build hosts

FCSC is counted from `#event_simpleName=OciContainerInfo` over a 25h lookback (`ngsiem.py:33`, `CONTAINER_HOST_LOOKBACK`). This is the best single signal per `oci-event-validation.md`. It tracks the official rolling average day to day and sits about 5 hosts low, against the ~59-host over-count from the old `Oci*` wildcard.

It is KAC-independent. `OciContainerInfo` is node-sensor telemetry gated by the `OciContainerSupport` system tag, not by Kubernetes Agentless Collection. So it catches a standalone Docker host that no K8s inventory would ever see. That is exactly the host that must be billed FCSC and would otherwise be missed.

The 25h window is calibrated to the event's 24h retransmit. A long-running container re-emits `OciContainerInfo` every 24h with `OciContainerInfoRetransmitted = 1`, so a 25h window catches at least one emission per still-running container. A container that started and stopped inside the window also leaves its `OciContainerInfo` behind. The window absorbs churn on its own.

**The older-build hosts can be counted.** Some hosts run containers but never send `OciContainerInfo`, because their sensor build predates it or `OciContainerSupport` is off. On talon_1 that is 36 hosts on builds like 18308, 7604, 8002, 7205. They are not invisible. They send `OciContainerStarted` and `OciContainerHeartbeat`, so the tool can tell they ran containers. Measured against the official 72.9 (`oci-event-validation.md`, section 2):

- `OciContainerInfo` alone: 68.0, about 5 low.
- `OciContainerInfo ∪ OciContainerStarted`: 79.1, about 6 high.
- adding `OciContainerHeartbeat`: 90.7, about 18 high.

No event union lands exactly on billing. For a showback tool whose per-tag numbers already run over the CID total, counting these hosts with `OciContainerInfo ∪ OciContainerStarted` is consistent. It errs generous and counts every host that shows container activity. The count query becomes that union. The CID total from the API (Layer 1) stays the exact billed number regardless, so the generosity lives only in the per-tag showback where it belongs.

`OciContainerInfo` alone stays available as the billing-faithful option if exact CID-level tracking is wanted instead of catching every container host. That is the one reversible choice in this section.

### Evidence: the same event carries identity

`OciContainerInfo` carries `OciContainerName`, `OciContainerImageId`, and `OciContainerEngineType` alongside `OciContainerId`. So the per-host justification is built from the same event that drives the count, with no second data source and no KAC dependency. `OciContainerEngineType` distinguishes Docker, containerd, and Podman, which is what proves a standalone Docker host is a container host.

The current count query is `groupBy(aid) | select([aid])`. The evidence query adds the identity fields:

```
#event_simpleName=OciContainerInfo
| groupBy([aid], function=collect([OciContainerName, OciContainerImageId, OciContainerEngineType]))
```

The evidence report is a new read. Older-build hosts counted via `OciContainerStarted` will have no image identity here, because `Started` carries none. Their evidence is the start event itself, which shows a container ran without naming its image.

### K8s enrichment: kubernetes_containers, evidence only

`falcon_search_kubernetes_containers` gives rich namespace, pod, and registry data, but only where KAC is deployed. It is demoted from any counting role to best-effort enrichment layered on top of the `OciContainerInfo` evidence for hosts that happen to be in a K8s cluster. It never sets the count, because it cannot see the standalone Docker host.

## Robust to ephemerality

Ephemeral workloads were the stated worry. They reconcile because consumption is measured in sensor-hours, the same unit billing measures in.

A container that lived three hours contributes three sensor-hours, not a whole license. A tag whose hosts churn contributes its actual occupied hours. Billing computes its number the same way, by averaging hourly readings over 28 days. Both the CID total and each tag's consumption are hourly averages, so churn averages out rather than accumulating into a discrepancy.

## What changes in the code

Pointers only. Implementation is a separate step, sequenced as its own commits.

- **Populate the CID total.** Store `get_hourly_usage` per-SKU rows per CID per date into `billing_averages`, with `selected_cids` set. This is the table the dead `log_to_csv` writer was supposed to fill (`how-chargeback-works.md`).
- **Per-tag showback view.** Compute `Consumed[tag,sku]` from `hourly_tag_counts` and report it beside the CID total. No multi-tag split. The existing once-per-tag counting is kept.
- **FCSC count union.** Extend the count query from `OciContainerInfo` to `OciContainerInfo ∪ OciContainerStarted` so older-build container hosts are counted, with `OciContainerInfo` alone retained as a flag-selectable option.
- **FCSC evidence report.** Add the identity-field query above and a per-host, per-tag rollup of images and engines. Note which hosts are `Started`-only and carry no image identity.
- **Reconciliation view.** Show the tool's NG-SIEM estimate next to the API total per SKU, including the direction and size of the gap, rather than only one number. This also fixes what the broken `verify` command was reaching for.

## Open questions carried forward

- What source does the official count use for the ~5 FCSC hosts that send no `OciContainerInfo`? `OciContainerInfo ∪ OciContainerStarted` runs 6 high, so the exact rule is still open (`oci-event-validation.md`).
- Do K8s-platform sensors count toward `containers` or `lumos`? This decides whether the 16–18 K8s sensors per hour belong in the FCSC or FMC total.
- On a Flight Control parent, does `search-all` return child-tenant events, and does `sensor_logs` need a real CID key to keep tenants apart (`how-chargeback-works.md`)?
