# Auto-Select Algorithm: GUID Slicing vs Single Query

## Flag

`--partition-auto` — per-phase automatic decision. Requires `--partition-ldap`. Supersedes `--partition-threshold`.

## Inputs

| Symbol | Source | Description |
|--------|--------|-------------|
| `C` | count query | object count for this phase |
| `S` | `--ldap-interval` | seconds between new LDAP searches |
| `Sj` | `--ldap-jitter` | jitter percentage (0–100) |
| `P` | `--ldap-page-interval` | seconds between continuation pages |
| `Pj` | `--ldap-page-jitter` | jitter percentage (0–100) |
| `PS` | hardcoded 200 | page size in `_iter_paged` |
| `W` | `--run-start` / `--run-end` | daily window in seconds (86400 if no window) |

## Average delays

```
avg_search = S × (1 + Sj / 200)
avg_page   = P × (1 + Pj / 200)
```

Jitter is uniform `[0, Sj%]`, so the expected addition is `Sj/2 %`.

## Time estimate: Original (single query)

```
pages        = ceil(C / PS)
continuations = pages - 1

T_original = 1 × avg_search + continuations × avg_page
```

## Time estimate: GUID slicing (256 queries)

```
per_slice_objects       = C / 256
per_slice_pages         = ceil(per_slice_objects / PS)
per_slice_continuations = max(0, per_slice_pages - 1)
total_continuations     = 256 × per_slice_continuations

T_sliced = 256 × avg_search + total_continuations × avg_page
```

## Decision logic

Pure speed is not the only axis. Resume granularity matters when a phase can't finish in one window:

```
if T_original ≤ W:
    → single query (faster, completes in one window)

elif T_sliced ≤ W:
    → GUID slicing (original won't finish; sliced will)

else:
    → GUID slicing (neither finishes in one window, but
      sliced checkpoints per-slice — original restarts
      from scratch each day and NEVER completes)
```

Without `--run-start`/`--run-end`, W = 86400 (full day). The decision simplifies to: use original unless it takes more than 24 hours.

## Why resume granularity is the deciding factor

Without GUID slicing, `--resume` granularity is per-phase. If a phase takes 12h but the window is 9h, it restarts from page 1 every day — it never finishes. GUID slicing checkpoints each of the 256 slices independently, so 9 hours of progress survives across days.

## Worked examples

**S=120s, Sj=50%, P=120s, Pj=50%, PS=200, Window=9h (32400s)**

```
avg_search = 150s, avg_page = 150s
```

| Phase | C | T_original | Fits 9h? | T_sliced | Decision |
|-------|------|------------|----------|----------|----------|
| users | 50020 | 150 + 250×150 = 37650s (10.5h) | NO | 256×150 = 38400s (10.7h) | GUID slicing (incremental resume) |
| groups | 554 | 150 + 2×150 = 450s (7.5m) | YES | 38400s (10.7h) | single query |
| computers | 30011 | 150 + 149×150 = 22500s (6.3h) | YES | 38400s (10.7h) | single query |
| gpos | 5 | 150 + 0×150 = 150s (2.5m) | YES | 38400s (10.7h) | single query |
| ous | 3601 | 150 + 17×150 = 2700s (45m) | YES | 38400s (10.7h) | single query |
| containers | 19 | 150 + 0×150 = 150s (2.5m) | YES | 38400s (10.7h) | single query |

## Log output format

```
INFO: [auto] users: 50020 objects — single-query 10.5h (exceeds 9.0h window), GUID-slicing 10.7h → GUID slicing (incremental resume)
INFO: [auto] groups: 554 objects — single-query 7.5m (fits 9.0h window) → single query
INFO: [auto] computers: 30011 objects — single-query 6.3h (fits 9.0h window) → single query
INFO: [auto] gpos: 5 objects — single-query 2.5m (fits 9.0h window) → single query
INFO: [auto] ous: 3601 objects — single-query 45.0m (fits 9.0h window) → single query
INFO: [auto] containers: 19 objects — single-query 2.5m (fits 9.0h window) → single query
```

## Edge case: no time window set

W = 86400s. The algorithm becomes: use single query unless the phase takes more than a day. Without pacing (`--ldap-interval 0`), everything completes instantly → always single query. This is correct — GUID slicing only has value when pacing makes phases long enough to span windows.

## Implementation notes

- Count query per phase: reuse existing `count_exceeds()` — it already does a 950-entry paged search through the monkey-patch. Check cookie presence to determine if count > 950. For the estimate, treat cookie-present as "at least 951" and use 951 as a lower bound (conservative: biases toward slicing).
- For exact count when cookie is present: continue paging. Or accept the lower bound — it only matters when T_original is near W.
- `--partition-auto` and `--partition-threshold` are mutually exclusive. Auto supersedes threshold if both given.
