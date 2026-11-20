# BloodHound.py
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/). This branch is a modified BloodHound.py CE build for red team use: in-process LDAP obfuscation through [ldapx-py](https://github.com/j0hnZ3RA/ldapx-py), LDAP query rate control, and resume after a stopped collection. It writes BloodHound CE JSON and is **only compatible with BloodHound CE**.

Obfuscation, SOCKS5, waits, resume, and logging are described in Features below. Requires **Python 3.9+**.

## Features

- **In-process ldapx-py obfuscation.** `--obf-filter`, `--obf-basedn`, `--obf-attrlist`, and `--obf-attrentries` rewrite each LDAP search in-process. No Go binary or local proxy. Works with standard DNS/`-dc` collection and with `--target`. `--use-ldaps` works alongside obfuscation (`--ldap-channel-binding` is deprecated; CBT is automatic on LDAPS). Recommended default: `--obf-filter OGDR --obf-attrlist RD --obf-basedn OX`. Every letter, what it does, and which codes to skip are in [LDAP obfuscation](#ldap-obfuscation-ldapx-py).
- **SOCKS5.** `--socks` sends LDAP, LDAPS, GC, and Kerberos TCP/88 through one SOCKS5 proxy (`socks5://[user:pass@]host:port`). DNS SRV lookups stay local (or use `-ns`). With `--target`, DNS is skipped entirely.
- **Two LDAP waits.** `--ldap-interval` spaces new searches and `member;range=` follow-ups. `--ldap-page-interval` spaces continuation pages of the same search. Each wait has its own jitter, and jitter only makes the gap longer.
- **Host throttle.** `--throttle` spaces Session, LocalAdmin, LoggedOn, RDP, DCOM, PSRemote, and Experimental RPC calls. Its jitter can make one wait shorter or longer. Durations accept `ms`, `s`, `m`, and `h`.
- **Large searches.** `--partition-ldap` splits schema, users, groups, computers, GPOs, OUs, and containers into 256 `objectGUID` slices.
- **Resume.** `--resume` keeps finished JSON and continues at the next phase, or at the next unfinished slice when partitioning is on. Works with or without `--outputprefix`.
- **Safe JSON.** Each output file is written to a partial file and renamed only after the `meta` footer is flushed.
- **Progress.** The console prints one line when a phase starts, `Found N users` when it finishes, and `users: 14 LDAP searches` for that section. Page lines such as `Schema page 4, 300 objects` appear while an LDAP interval is set.

## Installation
This repository is a BloodHound **CE** ingestor (`bloodhound-ce-ldapx`). It is not the legacy `bloodhound` / `bloodhound-python` package.

* Via pip: `pip install bloodhound-ce-ldapx`
* Via pipx: `pipx install bloodhound-ce-ldapx`
* From this tree: `pip install .`

That adds `bloodhound-ce-ldapx` to your PATH. `python bloodhound.py` from the repo root also works. `pip install` pulls [ldapx-py](https://github.com/j0hnZ3RA/ldapx-py) (`ldapx>=0.5.0`) and `ldap3-ad-auth` from PyPI. There is no Go toolchain or bundled ldapx binary.

## Usage
To use the ingestor, at a minimum you will need credentials of the domain you're logging in to. Credentials can be specified as username + password, NT hash or AES keys, or a Kerberos TGT in a ccache file.
You will need to specify the `-u` option with a username of this domain (or `username@domain` for a user in a trusted domain). If you have your DNS set up properly and the AD domain is in your DNS search list, then BloodHound.py will automatically detect the domain for you. If not, you have to specify it manually with the `-d` option.

By default BloodHound.py will query LDAP and the individual computers of the domain to enumerate users, computers, groups, trusts, sessions and local admins. 
If you want to restrict collection, specify the `--collectionmethod` parameter, which supports the following options (similar to SharpHound):
- *Default* - Performs group membership collection, domain trust collection, local admin collection, and session collection
- *Group* - Performs group membership collection
- *LocalAdmin* - Performs local admin collection
- *RDP* - Performs Remote Desktop Users collection
- *DCOM* - Performs Distributed COM Users collection
- *Container* - Performs container collection (GPO/Organizational Units/Default containers)
- *PSRemote* - Performs Remote Management (PS Remoting) Users collection
- *DCOnly* - Runs all collection methods that can be queried from the DC only, no connection to member hosts/servers needed. This is equal to Group,Acl,Trusts,ObjectProps,Container
- *Session* - Performs session collection
- *Acl* - Performs ACL collection
- *Trusts* - Performs domain trust enumeration
- *LoggedOn* - Performs privileged Session enumeration (requires local admin on the target)
- *ObjectProps* - Performs Object Properties collection for properties such as LastLogon or PwdLastSet
- *All* - Runs all methods above, except LoggedOn
- *Experimental* - Connects to individual hosts to enumerate services and scheduled tasks that may have stored credentials

Multiple collectionmethods should be separated by a comma, for example: `-c Group,LocalAdmin`

You can override some of the automatic detection options, such as the hostname of the primary Domain Controller if you want to use a different Domain Controller with `-dc`, or specify your own Global Catalog with `-gc`.

Host collection (`LocalAdmin`, `Session`, `LoggedOn`, `DCOM`, `RDP`, `PSRemote`, `Experimental`) connects to computers over SMB/RPC. `--ldap-interval` does not slow those calls; `--throttle` does. `--socks` does not tunnel host SMB/RPC.

## Examples

Recommended obfuscation in these commands is `--obf-filter OGDR --obf-attrlist RD --obf-basedn OX`. Drop the `--obf-*` flags for a vanilla query shape. Drop every wait flag for stock BloodHound.py speed.

**Fastest (stock BloodHound speed).** No `--ldap-interval`, `--ldap-page-interval`, `--throttle`, or `--partition-ldap`. New searches and continuation pages go out as soon as the DC answers, same burst as upstream BloodHound.py. Obfuscation still rewrites the query; it does not add a sleep.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  -c DCOnly --outputprefix corp --zip \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX
```

Use `-c All` for host collection at the same unpaced speed. `--socks` / `--target` / `--use-ldaps` can be added without changing the burst.

The next three are the same **most-OPSEC** shape: Kerberos, LDAPS, SOCKS to a DC IP, stronger collection-safe chains (`COGDR` / `CRD` / `COX`), 50% LDAP jitter (only lengthens the wait), and a file log instead of `-v`. `--throttle` is omitted on DCOnly; add the noted throttle for `-c All`. Test in a lab and change the waits for the domain.

**Most OPSEC, a bit speedy.** New searches wait 15–22.5s. Continuation pages wait 3–4.5s. No `--partition-ldap`, so a typical DCOnly run is tens of minutes plus DC time, not hours.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter COGDR --obf-attrlist CRD --obf-basedn COX \
  --ldap-interval 15s --ldap-jitter 50 \
  --ldap-page-interval 3s --ldap-page-jitter 50 \
  --log-file corp-opsec-fast.log
```

For `-c All`, add `--throttle 30s --throttle-jitter 50` so host RPC waits 15–45s.

**Most OPSEC, medium speed.** New searches wait 1–1.5 minutes. Continuation pages wait 8–12s. Still no partition. Expect a few hours on a medium directory.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter COGDR --obf-attrlist CRD --obf-basedn COX \
  --ldap-interval 1m --ldap-jitter 50 \
  --ldap-page-interval 8s --ldap-page-jitter 50 \
  --log-file corp-opsec-medium.log
```

For `-c All`, add `--throttle 3m --throttle-jitter 50` so host RPC waits 1.5–4.5 minutes.

**Most OPSEC, slow.** New searches and each `objectGUID` slice wait 5–7.5 minutes. Continuation pages wait 20–30 seconds. `--partition-ldap` splits schema, users, groups, computers, GPOs, OUs, and containers into 256 slices, so a DCOnly run is hours to days.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp --partition-ldap \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter COGDR --obf-attrlist CRD --obf-basedn COX \
  --ldap-interval 5m --ldap-jitter 50 \
  --ldap-page-interval 20s --ldap-page-jitter 50 \
  --log-file corp-opsec-slow.log
```

For `-c All`, add `--throttle 10m --throttle-jitter 50` so host RPC waits 5–15 minutes.

Standalone obfuscation (no `--target`): DNS/`-dc` collection with the recommended chains and native `--use-ldaps`, at stock speed.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --use-ldaps -c DCOnly --outputprefix corp \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX
```

Standalone SOCKS (no `--target`): DNS discovery stays local (or `-ns`); LDAP/LDAPS/GC and Kerberos TCP/88 go through the proxy.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --socks socks5://user:pass@127.0.0.1:1080 \
  --use-ldaps -c DCOnly --outputprefix corp \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX
```

DC-only collection to a raw DC IP, LDAPS, and a SOCKS5 proxy, with a short delay. New searches wait 4–4.8s. Later pages of the same search wait 2–2.8s. Console stays at info; the debug trace goes to `corp.log`.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --log-file corp.log
```

The same command after it stopped. Finished phases are skipped. The phase that was in progress is collected again. Output files keep the prefix and the original timestamp: `corp_<timestamp>_users.json`.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp --resume \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --log-file corp.log
```

A directory of about 20000 objects, split into `objectGUID` slices, with a moderate wait. The 30s search interval is between slices. The 5s page interval is between pages inside one slice. Together the two waits are about 21 minutes plus response time (see LDAP pacing).

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  -c DCOnly --outputprefix corp --partition-ldap \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX \
  --ldap-interval 30s --ldap-jitter 20 \
  --ldap-page-interval 5s --ldap-page-jitter 40 \
  --log-file corp.log
```

All collection methods, including host RPC. LDAP waits match the short SOCKS example (4–4.8s searches, 2–2.8s pages). Each Session, LocalAdmin, RDP, DCOM, PSRemote, and LoggedOn call waits about 1s, plus or minus 20%. `--socks` does not tunnel those host calls.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local \
  -c All --outputprefix corp \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --throttle 1s --throttle-jitter 20 \
  --log-file corp.log
```

Reuse a ccache instead of requesting a new TGT. If the cache already holds `ldap/dc01.domain.local`, the service-ticket request is skipped as well. `-no-pass` works because the password is not needed.

```
bloodhound-ce-ldapx -u USER -k -no-pass -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --target 10.1.1.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX
```


## LDAP obfuscation (ldapx-py)
BloodHound.py CE rewrites every LDAP `SearchRequest` in-process with [ldapx-py](https://github.com/j0hnZ3RA/ldapx-py). There is no Go binary and no local LDAP proxy. The filter is parsed to an AST, each letter in your chain is applied left to right, and the result is compiled straight to ldap3 ASN.1. That is why OID spacing, garbage clauses, and `--partition-ldap` `objectGUID=\xx*` bytes survive ldap3’s string parser.

What is rewritten:
- **Filter** (`--obf-filter`) — the LDAP search filter (`(objectClass=user)`, boolean trees, SID/GUID clauses, …).
- **BaseDN** (`--obf-basedn`) — the search base (`DC=domain,DC=local`, schema DN, …).
- **AttrList** (`--obf-attrlist`) — the attribute names requested in the search.
- **AttrEntries** (`--obf-attrentries`) — attribute *names on entries* (modify/add style). BloodHound is a read-only collector, so this is optional.

What is **not** rewritten:
- RootDSE reads (`search_base=""`, BASE scope).
- Schema-NC walks (the object-type GUID map). Garbage or OID attr names there break paging and `schemaIDGUID` lookups.
- `member;range=` follow-ups keep the range attribute unobfuscated so paging of large groups still works.

The first rewrite of a given (base, filter, attributes) is cached and reused on later pages of that search. Active Directory binds the paging cookie to the filter, so `G`/`D`/`R` must not change between page 1 and page 2.

`--obf-*` works with DNS discovery, `-dc`, and `--target`. Hidden aliases `--ldapx-filter` / `--ldapx-basedn` / `--ldapx-attrlist` / `--ldapx-attrentries` / `--ldapx-option` still work. `--ldapx-ldaps` was removed; use `--use-ldaps`.

With `-v` or `--log-file`, each search logs the original and rewritten filter, BaseDN, and attribute list. The DC still returns the original objects.

### Recommended chains
Use these for collection. They change how the query looks on the wire without changing which objects BloodHound gets back.

| Goal | Flags |
| --- | --- |
| **Recommended default** | `--obf-filter OGDR --obf-attrlist RD --obf-basedn OX` |
| Stronger, still collection-safe | `--obf-filter COGDR --obf-attrlist CRD --obf-basedn COX` |
| Light (case only) | `--obf-filter C --obf-basedn C` |
| Domain-root GUID/SID as well | add `--obf-basedn U` or `I` (only the domain-root base becomes `<GUID=…>` / `<SID=…>`) |

Example:
```
bloodhound-ce-ldapx -u user -p Pass -d domain.local -c DCOnly -v \
  --target 10.11.10.1 --use-ldaps \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX
```

Why that default:
- **Filter `OGDR`** — attribute names as spaced OIDs (`objectClass` → `oID.2.5.4.0`), extra garbage clauses that never match, double-negation (`(!!(…))`), and shuffled AND/OR order. Same result set.
- **AttrList `RD`** — shuffle requested attributes and duplicate some of them. The server still returns `member`, `objectSid`, and so on by name.
- **BaseDN `OX`** — RDN types as OIDs and hex-escaped values (`DC=domain` → `oID.0.9.2342…=do\6dain`). Still the same naming context.

Do **not** pass `--obf-attrlist ORD`. AttrList `O` (OID names on the *request attribute list*) is ignored here: BloodHound looks up `member` / `schemaIDGUID` by LDAP name, so OID keys would break collection. `--obf-attrlist RD` is the working equivalent.

### Filter codes (`--obf-filter`)

| Code | What it does | For BloodHound |
| --- | --- | --- |
| `O` | Rewrite attribute names to OIDs, with extra spaces/zeros (`cn` → `oID.2.5.4.3`) | Recommended |
| `G` | Append random never-matching garbage clauses | Recommended (cached per search so paging stays valid) |
| `D` | Wrap clauses in even numbers of NOT | Recommended |
| `R` | Shuffle AND/OR child order | Recommended |
| `C` | Randomize character case | Safe, optional |
| `S` | Insert spaces in attribute names | Safe, optional |
| `X` | Hex-encode assertion values (`admin` → `ad\6din`) | Safe, optional |
| `T` | Replace tautologies (`(objectClass=*)` style always-true) with equivalents | Safe, optional |
| `B` | Nest extra AND/OR that do not change the match | Safe, optional |
| `M` | De Morgan rewrite of boolean trees | Safe, optional |
| `F` | Toggle `objectCategory` short name vs config-NC DN | Optional; this tool supplies the config NC |
| `b` / `d` | Break/decompose bitwise (`userAccountControl`) matches | Optional; keep if you rely on UAC filters |
| `Z` | Prepend zeros to numeric values | Optional |
| `s` | Split equality into substrings | Optional |
| `t` | Timestamp garbage suffix | Optional |
| `N` / `n` | Map names to ANR / ANR garbage | Skip — different search |
| `A` | Equality → approx match (`~=`) | Skip — different match |
| `I` / `E` | Equality by inclusion/exclusion | Skip — different match |
| `x` | Equality → extensible match | Skip |
| `P` | `dnAttributes` noise | Skip |
| `L` | Transitive evaluation on link attributes | Skip |

Letters are applied left to right. `OGDR` means OID, then garbage, then double-negation, then reorder.

### BaseDN codes (`--obf-basedn`)

| Code | What it does | For BloodHound |
| --- | --- | --- |
| `O` | RDN attribute types as OIDs | Recommended |
| `X` | Hex-encode RDN values | Recommended |
| `C` | Random case | Safe, optional |
| `S` | Spacing in RDN types | Safe, optional |
| `Q` | Quote RDN values | Safe, optional |
| `U` | Replace the base with `<GUID=domainGUID>` | Only when the base is **exactly** the domain root (or another registered NC). OU and single-object lookups are left unchanged so they do not resolve to the domain object. |
| `I` | Replace the base with `<SID=domainSID>` | Same exact-NC rule as `U` |
| `W` | Well-known GUID form (`<WKGUID=…>`) | Only well-known container prefixes; otherwise a no-op |

BloodHound registers the domain object’s GUID/SID after the first domain read, so `U`/`I` work without `--obf-option BaseDNGuid=…`.

### AttrList codes (`--obf-attrlist`)

| Code | What it does | For BloodHound |
| --- | --- | --- |
| `R` | Shuffle the requested attribute order | Recommended |
| `D` | Duplicate some attribute names | Recommended |
| `C` | Random case | Safe, optional |
| `G` | Add non-existent garbage names | Optional |
| `g` | Add extra existing attribute names | Optional (slightly larger replies) |
| `O` / `o` | Rewrite names to spaced OIDs | **Ignored** (warning). Named lookups would break. |
| `W` | Replace the list with `*` | Avoid — changes what comes back |
| `w` | Append `*` | Avoid |
| `p` | Append `+` (operational attributes) | Avoid |
| `e` | Empty the list | Avoid |

`W` / `w` / `p` / `e` still run if you pass them, and they emit a warning. They can break JSON parsing.

### AttrEntries codes (`--obf-attrentries`)
BloodHound does not add or modify objects. If you still enable this:

| Code | What it does | For BloodHound |
| --- | --- | --- |
| `C` | Random case on entry attribute names | Safe |
| `R` | Reorder entry attributes | Safe |
| `O` | OID names on entries | Skip — same named-lookup problem as AttrList `O` |

### Options (`--obf-option KEY=VALUE`)
Repeat the flag for more than one option. Common knobs (ldapx defaults in parentheses):

| Option | Default | Used by |
| --- | --- | --- |
| `FiltCaseProb` | `0.5` | Filter `C` |
| `FiltGarbageMaxElems` / `FiltGarbageSize` | `1` / `10` | Filter `G` |
| `FiltOIDMaxSpaces` / `FiltOIDMaxZeros` | `2` / `2` | Filter `O` |
| `FiltDblNegMaxDepth` / `FiltDblNegProb` | `10` / `0.5` | Filter `D` |
| `BDNCaseProb` | `0.5` | BaseDN `C` |
| `BDNHexValueProb` | `0.3` | BaseDN `X` |
| `AttrsDuplicateProb` | `0.3` | AttrList `D` |

Example: `--obf-filter OGDR --obf-option FiltGarbageMaxElems=2 --obf-option FiltOIDMaxSpaces=4`.

### Targeting and SOCKS flags

| Flag | What it does |
| --- | --- |
| `--target HOST[:PORT]` | Connect to this DC without DNS discovery. Port defaults to 389, or 636 with `--use-ldaps`. An IP works when local DNS cannot resolve the DC. |
| `--socks URL` | SOCKS5 proxy for LDAP/LDAPS/GC and Kerberos TCP/88, for example `socks5://127.0.0.1:1080`. |
| `--use-ldaps` | LDAP over TLS (port 636 / GC 3269). Channel binding is automatic. |
| `--ldaps-legacy-tls` | TLS 1.2 and legacy ciphers for LDAPS (old DCs). |

PySocks is installed with BloodHound.py and is required for `--socks`. The SOCKS5 proxy must be able to reach the DC on LDAP (389, or 636 with `--use-ldaps`), the Global Catalog (3268, or 3269 with `--use-ldaps`), and Kerberos TCP/88. Optional credentials: `socks5://user:pass@host:port`.

How targeting works:
- BloodHound transforms each `SearchRequest` in-process and connects directly to the DC (or through `--socks`). `--use-ldaps` is native TLS; `--ldap-channel-binding` is deprecated because CBT is automatic on LDAPS via `ldap3-ad-auth`.
- `--socks` tunnels LDAP/LDAPS/GC TCP and Kerberos TCP/88. DNS SRV/A/AAAA lookups are not tunneled (use `-ns` if needed). With `--target` + `--socks`, DNS is skipped and every LDAP/Kerberos connection is tunneled. The proxy resolves hostnames (`rdns=True`). Host SMB/RPC is never tunneled.
- Kerberos encryption follows the credential you passed. A password prefers AES and uses RC4 only if the KDC rejects AES. `--hashes` uses RC4, because an NT hash cannot produce an AES key. `-aesKey` uses that AES key only.
- With `--target`, Kerberos SPNs use `-dc` when it is a real FQDN, otherwise `dnsHostName` from RootDSE. If `-d` is given, the base DN is derived from it even when DNS lookups fail.

`-k` reads `KRB5CCNAME`. A cached TGT is used instead of requesting a new one. A cached `ldap/<dc fqdn>` service ticket is used for the bind, which skips both the TGT request and a new service-ticket request. `-no-pass` works in that case because no password is needed to renew either ticket.

## LDAP pacing
To avoid tripping an LDAP query-rate threshold on a Domain Controller, you can slow BloodHound down so it trickles LDAP searches instead of bursting them.

| Flag | Default | What it does |
| --- | --- | --- |
| `--ldap-interval DURATION` | off | Minimum wait before a new LDAP search and before each `member;range=` follow-up, measured from when the previous search finished. A plain number is seconds. Suffixes `s`, `m` and `h` are accepted (`300`, `300s`, `5m`, `1h`). Continuation pages use `--ldap-page-interval` instead. |
| `--ldap-jitter PERCENT` | `0` | Extra random delay on top of `--ldap-interval` only. Range 0–100. The extra wait is `0` to `interval * PERCENT/100`, so a gap only gets longer. Requires `--ldap-interval`. |
| `--ldap-page-interval DURATION` | off | Minimum wait before a continuation page, the request that sends the previous paging cookie. Same duration syntax as `--ldap-interval`. Off by default, so later pages follow as soon as the previous page returns. |
| `--ldap-page-jitter PERCENT` | `0` | Extra random delay on top of `--ldap-page-interval` only. Range 0–100. Requires `--ldap-page-interval`. |
| `--throttle DURATION` | off | Minimum spacing between host RPC calls (Session, LocalAdmin, LoggedOn, RDP, DCOM, PSRemote, Experimental). A plain number is milliseconds. Suffixes `ms`, `s`, `m` and `h` are accepted (`500`, `500ms`, `2s`, `1m`). |
| `--throttle-jitter PERCENT` | `0` | Moves a host wait both below and above `--throttle`. The wait is never negative. Requires `--throttle`. |
| `--partition-ldap` | off | Split schema, users, groups, computers, GPOs, OUs and containers into 256 `objectGUID` slices. `--ldap-interval` spaces the slices. `--ldap-page-interval` spaces pages inside a slice. `--resume` skips finished slices. |

At startup BloodHound logs the active setting, for example `New LDAP searches at least 30s apart, plus 0-20% jitter. LDAP pages at least 5s apart, plus 0-40% jitter`. The first search is immediate.

A directory of about 20000 objects is about 100 pages at 200 objects per page, about 20 new DCOnly searches, and about 100 continuation pages. `--ldap-interval 30s --ldap-jitter 20` keeps those new searches 30–36 seconds apart, about 11 minutes. `--ldap-page-interval 5s --ldap-page-jitter 40` keeps the later pages 5.0–7.0 seconds apart, about 10 minutes. Together that is about 21 minutes plus response time. Setting only the search interval pulls the 100 pages as fast as the domain controller answers.

What waits for `--ldap-interval`:
- The first page of each search, including each `objectGUID` slice when `--partition-ldap` is set.
- Every `member;range=` follow-up. A group that contains all users is returned 1500 members at a time, so one large group is tens of extra searches.
- The rootDSE/schema server-info reads. When pacing is on these are read once on the first bind and reused.

What waits for `--ldap-page-interval`:
- Every later page of a paged search. BloodHound reads 200 objects per page. Each later page still sends the cookie from the page before it.

LDAP binds are not paced. Host SMB/RPC calls are paced only by `--throttle`. Because a wait is a plain sleep before the request (not a socket timeout), a long interval will not time the LDAP connection out; TCP keepalive is enabled to keep the session from being dropped as idle. A long sleep on a live connection does not request that page again. If the connection drops, BloodHound reconnects and sends that same cookie. Active Directory discards the paged result set with the connection and rejects the cookie (LDAP 00002040). The run stops there, with the pages already read left unrepeated, instead of starting that search again from the first page. Five failed reconnect attempts on the same page stop the run as well. With `--partition-ldap`, a crash repeats the open slice rather than the whole phase.

These flags work with or without `--target`, `--socks`, and `--obf-*`. All original BloodHound.py flags (`-ns`, `--dns-tcp`, `--use-ldaps`, `-gc`, `-c All`, and so on) are accepted in every mode. With `--target`, DNS flags and `-gc` are unused because the DC address comes from `--target`.

## Resume
`--resume` continues a collection that stopped. With `--outputprefix corp` the checkpoint is `corp_resume.json` and the output files are `corp_<timestamp>_users.json`, `corp_<timestamp>_groups.json`, and so on. Without a prefix the checkpoint is `bloodhound_resume.json`. If `--resume` is given without `--outputprefix` and the directory has exactly one `*_resume.json`, that checkpoint is used, including its saved prefix.

The file records the domain, the collection methods, the output timestamp, the output prefix, the finished phases, any finished `objectGUID` slices, and the schema GUID map.

Run the same command again with `--resume` and the same `--outputprefix`. Phases whose JSON is already complete are skipped. `meta.count` has to match the number of objects in `data`. The phase that was still in progress is collected again, and its file is replaced. A paging cookie is not reused: Active Directory drops it when the connection dies, so the interrupted phase starts its LDAP search over. Finished files are left as they are.

This covers every collection method, by finished phase: users, groups, computers, GPOs, OUs, containers, and the domain file. `ObjectProps` and `ACL` are part of those files, so the collection methods on the resumed command have to match. `LocalAdmin`, `Session`, `LoggedOn`, `DCOM`, `RDP`, `PSRemote`, and `Experimental` are one host pass: a stop in the middle repeats that whole pass, not a single computer. `DCOnly`, `Default`, and `All` resume whichever of those phases they include.

Each of those sections prints how many LDAP searches it sent, for example `users: 14 LDAP searches`. Host checks over SMB are not included in that number.

JSON is written to a `.partial` file and renamed onto the real name only after the `meta` footer is flushed. A crash leaves the previous phase's file valid and does not leave a half-written file for BloodHound to import.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -c DCOnly --outputprefix corp --resume
```

## Logging
`--log-file PATH` writes a timestamped debug log and overwrites that file. Each line looks like `2026-10-06 00:28:02 INFO: ...`. The file contains:

- BloodHound's own debug trace (collection, Kerberos, pacing, output files)
- When obfuscation is enabled, the original and rewritten filter, BaseDN, and attribute list for every search

LDAP response bodies are not written, so a domain's search results and schema do not land in the file. The console stays at the normal info level unless you also pass `-v`. A collection prints one info line as each phase starts (`Collecting users`), `Found 20 users` when it finishes, and `users: 14 LDAP searches` for how many LDAP searches that section sent. While either LDAP interval is set, each finished page also adds one line such as `Schema page 4, 300 objects`. Without an interval those page lines stay in the debug log. With both `-v` and `--log-file`, `-v` prints debug to the console as well.

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -c DCOnly --log-file bloodhound.log
```

## Guide
This is a full DC-only collection through a local SOCKS5 proxy, with in-process obfuscation and a short LDAP delay. Use it to check that authentication, rewriting, pacing, and JSON output all work before raising the interval for a larger domain.

1. Install BloodHound.py CE (`pip install .` from this tree). That also installs ldapx-py.
2. Start the SOCKS5 proxy and confirm it can open TCP connections to the DC on ports 389, 3268, and 88. For LDAPS, use 636 and 3269 instead and add `--use-ldaps`.
3. Run:

```
bloodhound-ce-ldapx -u USER -p PASS -d domain.local -dc dc01.domain.local -c DCOnly \
  --target 10.1.1.1 \
  --socks socks5://127.0.0.1:1080 \
  --obf-filter OGDR --obf-attrlist RD --obf-basedn OX \
  --ldap-interval 2s --ldap-jitter 50 \
  --zip --outputprefix domain \
  --log-file domain.log
```

`-dc dc01.domain.local` is the Kerberos SPN hostname. The sockets go to `--target` through `--socks`. Use a DC IP (or a name the proxy can resolve); the hop often has no DNS for the DC FQDN. `-d domain.local` supplies the base DN (`DC=domain,DC=local`) even when local DNS lookups fail. `bloodhound-ce-ldapx` and `python bloodhound.py` both work, including the ACL process pool on Windows.

4. Check the log:
   - `New LDAP searches at least 2s apart, plus 0-50% jitter`
   - `Kerberos traffic will be routed through SOCKS proxy 127.0.0.1:1080`
   - `LDAP traffic will be routed through SOCKS proxy 127.0.0.1:1080`
   - `Obfuscated filter (OGDR):` lines for rewritten searches
   - `Found N users`, `Found N computers`, `Found N groups`, then `Done in`
5. With `-v`, a rewritten search is logged as original then obfuscated. The DC still returns the original objects.

6. Output files are written in the current directory: `domain_<timestamp>_users.json`, `_computers.json`, `_groups.json`, `_domains.json`, `_gpos.json`, `_ous.json`, and `_containers.json`. `--zip` packs those JSON files into `domain_<timestamp>_bloodhound.zip` and removes the loose JSON. Import that zip into BloodHound CE.

Raise `--ldap-interval` once the short run looks right. A 2 second interval is only for a functional check. The runtime estimates in the pacing section are the ones to use on a production domain.

## Limitations
- Supports most, but not all BloodHound (SharpHound) features. GPO local groups are not supported; the other collection methods are implemented.
- `--socks` tunnels LDAP/LDAPS/GC and Kerberos TCP/88 only. Host collection (LocalAdmin, Session, LoggedOn, DCOM, RDP, PSRemote, Experimental) uses SMB/RPC on the local network and is not proxied.
- `--target` should be an address the SOCKS hop can connect to. A DC FQDN fails if the proxy cannot resolve it; pass the DC IP and keep `-dc` as the real hostname for Kerberos SPNs.
- Kerberos binds (`--auth-method kerberos`) require this host's clock to be within AD's skew of the DC. A `KRB_AP_ERR_SKEW` error means sync time, then retry. `--auth-method auto` falls back to NTLM.
- `--obf-attrlist` codes `O`/`o` are ignored. BloodHound reads attributes by LDAP name; OID rewriting would break `member`, `schemaIDGUID`, and similar lookups. Use `RD`.
- `--obf-basedn U`/`I` only rewrite a search base that is exactly a naming context (domain root). Single-object and OU bases stay unchanged.
- Schema-NC reads (the object-type GUID map) are not obfuscated. Filter rewrites are reused on later pages of the same search so AD paging cookies stay valid.

## Docker usage
1. Build container  
```docker build -t bloodhound .```  
2. Run container  
```docker run -v ${PWD}:/bloodhound-data -it bloodhound```  
After that you can run `bloodhound-ce-ldapx` inside the container, all data will be stored in the path from where you start the container.

## Credits
BloodHound.py was originally written by Dirk-jan Mollema, Edwin van Vliet and Matthijs Gielen from [Fox-IT (NCC Group)](https://fox-it.com/). BloodHound.py is currently maintained by Dirk-jan Mollema from [Outsider Security](https://outsidersecurity.nl). The implementation and data model is based on the original tool from [SpecterOps](https://specterops.io). Many thanks to everyone who contributed by testing, submitting issues and pull requests over the years.
