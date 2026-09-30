# Which OCI event identifies an FCSC host? Validation on talon_1

*Run 2026-09-30 with `/pstack:figure-it-out`, tenant talon_1 (CID ending 9a1f). Aggregates only; no host IDs are stored.*

## Summary

- **The current `Oci*` match over-counts FCSC by about 1.8x.** On the licensing basis (hourly average over 28 days), it gives 131.5 container hosts. SensorUsage reports 72.9. The ~59-host excess is billed as FCSC instead of FCS. **VERIFIED.**
- **`OciContainerInfo` is the best event signal**, but it isn't exact. It follows the official rolling average day to day (mean step error 0.047 hosts). Its level is 4.8 hosts (6.6%) low, and a longer lookback doesn't close the gap. **INCONCLUSIVE** as an exact reproduction of the official number.
- **`OciContainerEngineInfo` matches the 28-day level (+0.2), but not the daily movement.** All four of its predicted steps are about half the official steps (step error 0.28, about six times Info's), so the level match is incidental rather than evidence of the rule. **NOT VERIFIED.**
- The instrument calibrates. Replayed "hosts seen per hour" matches the official total within 0.7 hosts, and the daily steps match within 0.2.

## The licensing rule being replayed

These rules come from the user, and the SensorUsage response is consistent with them:

- Licensing counts the sensors seen in each hour and averages those hourly readings over the past 28 days (`get_hourly_usage`, not weekly).
- A host seen in hour H counts as a **container host (FCSC)** if a container ran on it in the trailing 24–25h. Otherwise it's an FCS non-container host.
- FCSC is licensed **per container host, not per container.** The API bears this out: `containers` (72.88) = `public_cloud_with_containers` (72.87) + `servers_with_containers` (0.01).

## 1. Distinct hosts per OCI event, one 25h window

Window: 2026-09-29T11:56Z to 2026-09-30T12:56Z. Source: `docs/oci-event-validation.json`, from `scripts/oci_event_validation.py`.

| Event | Hosts |
|---|---|
| SensorHeartbeat (all platforms) | 378 (Win 194, Lin 163, K8s 18, Android 2, Mac 1) |
| OciContainerTelemetry | 137 |
| OciContainerHeartbeat | 99 |
| OciContainerInfo | 82 |
| OciImageHeartbeat | 79 |
| OciContainerEngineInfo | 78 |
| OciContainerComplianceInfo | 60 |
| OciContainerStarted | 45 |
| OciContainerStopped | 31 |
| OciContainerPlumbingSummary | 25 |
| OciImageInfo | 10 |
| Any Oci* on a Linux host (what the tool counts) | 158 |

- **Telemetry is noise.** It is Linux-only and reached 137 of the 163 Linux hosts, and 101 of those 137 reported zero container starts in the window. This matches the investigation: it fires every 24h with no zero-guard.
- **Info-only-by-retransmit:** 55 of the 82 Info hosts sent *only* retransmitted Info (`OciContainerInfoRetransmitted=1`). These are long-running containers. A Started-based count would miss them.
- **EngineInfo ⊂ Info** on this window.
- **Started:** all 45 hosts had at least one non-rundown start. Whether `OciContainerIsRundown` is populated as `1` on this tenant is unverified.
- **Container evidence without Info:** 21 hosts sent OciContainerHeartbeat but no Info, and 15 sent Started but no Info. None of the 36 sent any Info in the prior 7 days. They run older or other sensor builds (18308, 7604, 8002, 7205 and others), while the Info hosts run 187xx–194xx.

**Caveat, `count(aid, distinct=true)`:** LogScale estimates distinct counts. On both runs it came out 1 low on the same 5 of 10 event types (Telemetry 136, ContainerHeartbeat 98, Info 81, ImageHeartbeat 78, EngineInfo 77). The counts above use `groupBy([event, aid]) | count()`, which is exact. The script's cross-check compares them against the host-level overlap table, and all five checks agree. Chargeback code shouldn't rely on `count(distinct=true)` for exact numbers.

## 2. Official comparison on the licensing basis

Source: `docs/fcsc-hourly-replay.json`, from `scripts/fcsc_hourly_replay.py --event-date 2026-09-28 --diff-days 4`.

**Official figure:** SensorUsage `get_hourly_usage` with `event_date:'2026-09-28'+period:'28'+selected_cids:'<own cid>'`:

- containers 72.88;
- public cloud without containers 214.58;
- servers without containers 7.98;
- workstations 16.09;
- mobile 0.85;
- lumos 8.81;
- total 321.2 hosts.

Each date's row is already the rolling 28-day average; `period:'1'` returns the same value.

**Replay:** for a sampled hour H, count the hosts with a SensorHeartbeat in H. Then count how many of them sent each candidate event in the 25h ending at H's end.

### Level test: 28 hours, one per day, rotating hour of day

| Candidate | Replay mean | vs official |
|---|---|---|
| hosts seen (calibration vs total 321.2) | 321.9 | +0.7 |
| Oci* (current tool) | 131.5 | **+58.7** |
| Info | 68.0 | −4.8 |
| EngineInfo | 73.0 | +0.2 |
| Info ∪ Started | 79.1 | +6.2 |
| Info ∪ Started ∪ ContainerHeartbeat | 90.7 | +17.8 |

EngineInfo ranged 61–105 across samples, with a spike on 5–7 Sept, so its mean carries about ±2 of sampling error. Info ranged 56–74.

### Step test: the rolling average's daily moves

A rolling 28-day mean moves by (day added − day dropped) / 28. Each official step from 25 to 28 Sept is predicted from 6 sampled hours on day t and on day t−28 (28 to 31 Aug). A candidate that is the real rule has to track these moves, not just the level.

| Date | Official Δ containers | Oci* | Info | EngineInfo | Info ∪ Started | Union |
|---|---|---|---|---|---|---|
| 09-25 | 0.378 | 1.113 | 0.280 | 0.048 | 0.292 | 0.393 |
| 09-26 | 0.371 | 0.399 | 0.423 | 0.125 | 0.357 | 0.452 |
| 09-27 | 0.473 | 0.429 | 0.452 | 0.202 | 0.333 | 0.536 |
| 09-28 | 0.533 | 0.488 | 0.518 | 0.250 | 0.423 | 0.589 |
| **Mean abs error** | | 0.213 | **0.047** | 0.282 | 0.087 | 0.054 |

The calibration steps match: hosts-seen predictions of 1.61, 1.42, 1.19 and 1.20 against official total steps of 1.6, 1.5, 1.1 and 1.3.

### Probe: is Info short because retransmits land just outside 25h?

No. With a 49h lookback, Info is still −4.84. Every host that sends Info at all is already inside 25h. So the gap is about 5 hosts that the official count includes and that never send Info. Where they come from is unverified. There are two candidate pools:

- the 36 older-build container hosts from section 1;
- the 16–18 K8s-platform sensors per hour, which never send Oci* events at all.

"About 5" is only the net difference, so the gross number of hosts counted in different ways could be larger.

## Verdicts

| Claim | Verdict |
|---|---|
| `Oci*` (with OciContainerTelemetry) over-counts FCSC hosts | **VERIFIED**: +58.7 of 72.9 on the licensing basis |
| `OciContainerInfo` over 25h reproduces the official FCSC count | **INCONCLUSIVE**: it tracks the dynamics, but its level is 6.6% low |
| `OciContainerEngineInfo` is the licensing signal | **NOT VERIFIED**: its level matches, but all 4 daily steps come in about 50% low |
| Hosts without Info can still be counted as container hosts | **PLAUSIBLE, not verified**: the ~5-host gap persists at 49h |
| SensorUsage without `selected_cids` returns this tenant's usage | **NOT VERIFIED**: it returned a far larger scope (~114k servers) |

## Recommendation for the tool

1. Replace `#event_simpleName=Oci*` in `ngsiem.py` (the FCSC queries and the `_FCS_QUERY` anti-join) with `#event_simpleName=OciContainerInfo` over a 25h lookback. That gets within about 5 hosts of billing instead of about 59.
2. Keep SensorUsage (`get_hourly_usage`, `period:'28'`, `selected_cids`) as the reference total. Report the NG-SIEM estimate next to it rather than instead of it.
3. Pass `selected_cids` in `billing.py`. Without it, the multi-tenant path reports the wrong scope even after its method names are fixed.

## Open questions

- What source does the official count use for the ~5 FCSC hosts that send no Info? Do K8s-platform sensors count toward `containers` or `lumos`? Testing Info ∪ ContainerHeartbeat restricted by sensor build, or asking the SensorUsage owners, would settle it.
- Does `event_date` cover the UTC day? The step test assumed it does, and it fit.
- Two sessions on one API client invalidated each other's bearer tokens mid-run. Both scripts' search paths should refresh on 401; `fcsc_hourly_replay.py` already does.

## Reproduce

```
python3 scripts/oci_event_validation.py --profile talon_1 --end 2026-09-30T12:56:00+00:00 --out docs/oci-event-validation.json
python3 scripts/fcsc_hourly_replay.py --profile talon_1 --event-date 2026-09-28 --diff-days 4 --out docs/fcsc-hourly-replay.json
```

Credentials come from the macOS Keychain inside the scripts and are never printed. Don't run more than one script at a time on the same API client.
