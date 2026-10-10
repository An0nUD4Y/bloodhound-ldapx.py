# BloodHound.py
![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/bloodhound.svg)
![License: MIT](https://img.shields.io/pypi/l/bloodhound.svg)

BloodHound.py is a Python ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/). This branch is a modified BloodHound.py CE build for red team use: LDAP obfuscation through ldapx, LDAP query rate control, and resume after a stopped collection. It writes BloodHound CE JSON and is **only compatible with BloodHound CE**.

It can send those searches through a managed [ldapx](https://github.com/Macmod/ldapx) proxy and the same SOCKS5 path used for Kerberos. Waits, resume, and logging are described in Features below.

## Features

- **ldapx proxy.** BloodHound starts ldapx, rewrites each search (filter, attribute list, and base DN), and forwards it to the DC. `--ldapx-ldaps` uses LDAPS upstream. TLS satisfies LDAP signing, and ldapx injects the channel binding. `-k` reuses a cached TGT or `ldap/<dc>` service ticket.
- **SOCKS5.** `--ldapx-socks` sends both the ldapx upstream connection and Kerberos TCP/88 through one proxy.
- **Two LDAP waits.** `--ldap-interval` spaces new searches and `member;range=` follow-ups. `--ldap-page-interval` spaces continuation pages of the same search. Each wait has its own jitter, and jitter only makes the gap longer.
- **Host throttle.** `--throttle` spaces Session, LocalAdmin, LoggedOn, RDP, DCOM, PSRemote, and Experimental RPC calls. Its jitter can make one wait shorter or longer. Durations accept `ms`, `s`, `m`, and `h`.
- **Large searches.** `--partition-ldap` splits schema, users, groups, computers, GPOs, OUs, and containers into 256 `objectGUID` slices.
- **Resume.** `--resume` keeps finished JSON and continues at the next phase, or at the next unfinished slice when partitioning is on. Works with or without `--outputprefix`.
- **Safe JSON.** Each output file is written to a partial file and renamed only after the `meta` footer is flushed.
- **Progress.** The console prints one line when a phase starts, `Found N users` when it finishes, and `users: 14 LDAP searches` for that section. Page lines such as `Schema page 4, 300 objects` appear while an LDAP interval is set.

## Installation
There are different install methods for BloodHound Community Edition (CE) and BloodHound legacy. You can only have one of the two tools installed at the same time, unless you use a virtual environment for both tools, or a package manager like pipx that automatically sets these up.

### BloodHound Legacy
The following install methods are available:
* Via pip: `pip install bloodhound`
* Via pipx: `pipx install bloodhound`
* By cloning this repository `git clone https://github.com/An0nUD4Y/bloodhound-ldapx.py` and running `pip install .` from the project directory.

The BloodHound.py Legacy installation will add a command line tool `bloodhound-python` to your PATH.

### BloodHound CE
The following install methods are available:
* Via pip: `pip install bloodhound-ce`
* Via pipx: `pipx install bloodhound-ce`
* By cloning this repository `git clone https://github.com/An0nUD4Y/bloodhound-ldapx.py`, checking out the CE branch `git checkout bloodhound-ce` and running `pip install .` from the project directory.

The BloodHound.py CE ingestor will add a command line tool `bloodhound-ce-python` to your PATH.

`pip install` also downloads [ldapx](https://github.com/Macmod/ldapx) v1.3.5 for the current operating system into the package (`bloodhound/bin`). You do not need a separate ldapx install or a Go toolchain. If that download fails, the same fetch runs the first time `--ldapx-target` is used. `--ldapx-binary` still selects a different executable.

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

Host collection (`LocalAdmin`, `Session`, `LoggedOn`, `DCOM`, `RDP`, `PSRemote`, `Experimental`) connects to computers over SMB/RPC. It does not go through ldapx. `--ldap-interval` does not slow those calls; `--throttle` does. With `--ldapx-target`, collect with `DCOnly` (or `Group`, `ACL`, `Trusts`, `ObjectProps`, `Container`) so every query stays on the Domain Controller path.

## Examples

**OPSEC-safe :** Keep new LDAP searches in the 2–5 minute band, continuation pages in the 5–20 second band, and host RPC calls in the 3–10 minute band. Jitter on both LDAP waits is 50% and only lengthens the minimum, so the flags use the bottom of each band: searches wait 2m–3m and pages wait 5–7.5s. Host jitter is also 50% and moves a 6m throttle to 3–9m. The console stays at info level. The debug trace, including each ldapx rewrite, goes to `corp-opsec.log`.
THIS MAY TAKE FEW HOURS TO DAYS TO COMPLETE, Please test in lab and modify the sleep times accordingly.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --ldapx-target 10.1.1.1:636 --ldapx-ldaps \
  --ldapx-socks socks5://127.0.0.1:1080 \
  --ldapx-filter OGDR --ldapx-attrlist Owp --ldapx-basedn OX \
  --ldap-interval 1m --ldap-jitter 50 \
  --ldap-page-interval 8s --ldap-page-jitter 50 \
  --throttle 3m --throttle-jitter 50 \
  --log-file bloodhound-logs.log -v
```


DC-only collection through ldapx, LDAPS, and a SOCKS5 proxy. New searches wait 4–4.8s. Later pages of the same search wait 2–2.8s. The console stays at info level and the debug trace goes to a file.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp \
  --ldapx-target 10.1.1.1:636 --ldapx-ldaps \
  --ldapx-socks socks5://127.0.0.1:1080 \
  --ldapx-filter OGDR --ldapx-attrlist Owp --ldapx-basedn OX \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --log-file corp.log
```

The same command after it stopped. Finished phases are skipped. The phase that was in progress is collected again. Output files keep the prefix and the original timestamp: `corp_<timestamp>_users.json`.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly --outputprefix corp --resume \
  --ldapx-target 10.1.1.1:636 --ldapx-ldaps \
  --ldapx-socks socks5://127.0.0.1:1080 \
  --ldapx-filter OGDR --ldapx-attrlist Owp --ldapx-basedn OX \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --log-file corp.log
```

A directory of about 20000 objects, split into `objectGUID` slices. The 30s search interval is between slices. The 5s page interval is between pages inside one slice. Together the two waits are about 21 minutes plus response time.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local \
  -c DCOnly --outputprefix corp --partition-ldap \
  --ldap-interval 30s --ldap-jitter 20 \
  --ldap-page-interval 5s --ldap-page-jitter 40 \
  --log-file corp.log
```

All collection methods, including host RPC. LDAP uses the two intervals above. Each Session, LocalAdmin, RDP, DCOM, PSRemote, and LoggedOn call waits about 1s, plus or minus 20%.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local \
  -c All --outputprefix corp \
  --ldap-interval 4s --ldap-jitter 20 \
  --ldap-page-interval 2s --ldap-page-jitter 40 \
  --throttle 1s --throttle-jitter 20 \
  --log-file corp.log
```

Reuse a ccache instead of requesting a new TGT. If the cache already holds `ldap/dc01.domain.local`, the service-ticket request is skipped as well. `-no-pass` works because the password is not needed.

```
bloodhound-ce-python -u USER -k -no-pass -d domain.local -dc dc01.domain.local \
  --auth-method kerberos -c DCOnly \
  --ldapx-target 10.1.1.1:636 --ldapx-ldaps \
  --ldapx-socks socks5://127.0.0.1:1080
```


## ldapx integration
BloodHound.py CE can run [ldapx](https://github.com/Macmod/ldapx) as a managed child process, so all LDAP searches are transformed by ldapx middlewares before they reach the Domain Controller. This replaces the manual `proxychains4 ldapx ...` + `bloodhound-ce-python -dc localhost` setup and also makes Kerberos work in that setup.

The ldapx binary is downloaded for you (see Installation). PySocks is installed with BloodHound.py and is required for `--ldapx-socks`. The SOCKS5 proxy must be able to reach the DC on LDAP (389, or 636 with `--ldapx-ldaps`), the Global Catalog (3268, or 3269 with `--ldapx-ldaps`), and Kerberos TCP/88.

Example:
```
bloodhound-ce-python -u user -p Pass -d domain.local -c DCOnly -v \
  --ldapx-target 10.11.10.1:636 --ldapx-ldaps \
  --ldapx-socks socks5://127.0.0.1:1080 \
  --ldapx-filter OGDR --ldapx-attrlist Owp --ldapx-basedn OX
```

### ldapx parameters

| Flag | ldapx flag | What it does |
| --- | --- | --- |
| `--ldapx-target HOST:PORT` | `-t` | Turns ldapx mode on. `HOST:PORT` is the real DC. The port defaults to 389, or 636 when `--ldapx-ldaps` is set. An IP works when local DNS cannot resolve the DC. |
| `--ldapx-ldaps` | `-s` | ldapx connects upstream with LDAPS. The local listener stays plaintext. Channel binding is injected on the bind. |
| `--ldapx-socks URL` | `-x` | SOCKS5 proxy for ldapx, for example `socks5://127.0.0.1:1080`. The same proxy is used for Kerberos TCP to port 88 of the target. |
| `--ldapx-filter CHAIN` | `-f` | Search-filter middleware chain. `OGDR` is OID attribute, garbage clauses, double-negative boolean, reorder boolean. |
| `--ldapx-attrlist CHAIN` | `-a` | Attribute-list middleware chain. `Owp` is OID attribute, add `*`, add `+`. |
| `--ldapx-basedn CHAIN` | `-b` | Base-DN middleware chain. `OX` is OID attribute and hex-encoded values. |
| `--ldapx-attrentries CHAIN` | `-e` | Attribute-entries middleware chain. |
| `--ldapx-option KEY=VALUE` | `-o` | Middleware option. Repeat the flag for more than one option. |
| `--ldapx-binary PATH` | | ldapx executable. Default: the bundled v1.3.5 binary, then `ldapx` on `PATH`. |
| `--ldapx-listen HOST:PORT` | `-l` | Local LDAP listener. Default `127.0.0.1:1389`. |
| `--ldapx-gc-listen HOST:PORT` | `-l` | Local Global Catalog listener. Default `127.0.0.1:13268`. |
| `--ldapx-decrypt-ccache PATH` | `--decrypt-ccache` | Overrides the ccache used for LDAPS channel binding. Normally generated for you. |
| `--ldapx-decrypt-hash HEX` | `--decrypt-hash` | Overrides the NT hash used for NTLM channel binding. With `--ldapx-ldaps`, the password or NT hash from the command line is passed automatically. |

Each letter in a chain is one ldapx middleware, applied left to right. ldapx prints the resolved names at startup (`FilterMiddlewares`, `AttrListMiddlewares`, `BaseDNMiddlewares`). With `-v` or `--log-file`, each search is logged twice: `Intercepted Search` is the original filter, and `Changed Search` is what was sent to the DC. `-v` alone also enables ldapx packet dumps in both directions (`-F 2 -R 2`); the schema reply alone is large. `--log-file` keeps the request trail and leaves response bodies out.

How it works:
- BloodHound starts two ldapx child processes: one LDAP listener and one Global Catalog listener. BloodHound speaks plaintext LDAP to these listeners; ldapx forwards to the target. With `--ldapx-ldaps` the upstream connection is LDAPS (target ports 636/3269), otherwise plaintext (389/3268). Do not combine with `--use-ldaps`: TLS to the target is handled by ldapx.
- Kerberos to port 88 of `--ldapx-target` uses the same SOCKS5 proxy, so no direct connection to the DC is made and no `proxychains` wrapper is needed.
- Kerberos encryption follows the credential you passed. A password prefers AES and uses RC4 only if the KDC rejects AES. `--hashes` uses RC4, because an NT hash cannot produce an AES key. `-aesKey` uses that AES key only.
- Kerberos SPNs always use the real DC FQDN, not the local listener. If `-dc` is set to a real FQDN it is only used as the SPN hostname (never as a connection target). If `-dc` is omitted, BloodHound reads `dnsHostName` from rootDSE through the ldapx listener before requesting tickets. DNS is not required in this mode: if `-d` is given, the base DN is derived from it even when all DNS lookups fail.

Channel binding and signing: with `--ldapx-ldaps`, BloodHound requests the `ldap/<dc fqdn>` service ticket (or reuses one already in the ccache), writes it to a temporary ccache when it is not already a file, and restarts ldapx with `--decrypt-ccache`. ldapx injects the LDAPS channel binding into that ticket. Active Directory treats the LDAPS session itself as LDAP signing, and it rejects a bind that also asks for SASL sign/seal (`00002029: Cannot bind using sign/seal on a connection on which TLS or SSL is in effect`). Searches after the bind therefore stay unsigned at the SASL layer, which is what lets ldapx rewrite them, while TLS on the upstream connection satisfies the signing requirement. A password is also passed as `--decrypt-password`, and an NT hash as `--decrypt-hash`, so an NTLM bind can be re-signed when channel binding is required. `--ldapx-decrypt-ccache` and `--ldapx-decrypt-hash` still override those values.

`-k` reads `KRB5CCNAME`. A cached TGT is used instead of requesting a new one. A cached `ldap/<dc fqdn>` service ticket is used for the bind and for ldapx, which skips both the TGT request and a new service-ticket request. `-no-pass` works in that case because no password is needed to renew either ticket.

Both ldapx processes are stopped automatically when BloodHound exits.

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

These flags work with or without `--ldapx-target`. Note that `--use-ldaps`, `--ldap-channel-binding`, `-ns`/`--dns-tcp`/`--dns-timeout`, `-gc` and `--disable-autogc` are tagged "Don't use while using with built in ldapx" in `--help`: the first two are rejected when combined with `--ldapx-target`, and the DNS/GC options have no effect in ldapx mode.

## Resume
`--resume` continues a collection that stopped. With `--outputprefix corp` the checkpoint is `corp_resume.json` and the output files are `corp_<timestamp>_users.json`, `corp_<timestamp>_groups.json`, and so on. Without a prefix the checkpoint is `bloodhound_resume.json`. If `--resume` is given without `--outputprefix` and the directory has exactly one `*_resume.json`, that checkpoint is used, including its saved prefix.

The file records the domain, the collection methods, the output timestamp, the output prefix, the finished phases, any finished `objectGUID` slices, and the schema GUID map.

Run the same command again with `--resume` and the same `--outputprefix`. Phases whose JSON is already complete are skipped. `meta.count` has to match the number of objects in `data`. The phase that was still in progress is collected again, and its file is replaced. A paging cookie is not reused: Active Directory drops it when the connection dies, so the interrupted phase starts its LDAP search over. Finished files are left as they are.

This covers every collection method, by finished phase: users, groups, computers, GPOs, OUs, containers, and the domain file. `ObjectProps` and `ACL` are part of those files, so the collection methods on the resumed command have to match. `LocalAdmin`, `Session`, `LoggedOn`, `DCOM`, `RDP`, `PSRemote`, and `Experimental` are one host pass: a stop in the middle repeats that whole pass, not a single computer. `DCOnly`, `Default`, and `All` resume whichever of those phases they include.

Each of those sections prints how many LDAP searches it sent, for example `users: 14 LDAP searches`. Host checks over SMB are not included in that number.

JSON is written to a `.partial` file and renamed onto the real name only after the `meta` footer is flushed. A crash leaves the previous phase's file valid and does not leave a half-written file for BloodHound to import.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -c DCOnly --outputprefix corp --resume
```

## Logging
`--log-file PATH` writes a timestamped debug log and overwrites that file. Each line looks like `2026-10-06 00:28:02 INFO: ...`. The file contains:

- BloodHound's own debug trace (collection, Kerberos, pacing, output files)
- ldapx startup and, for every search, the middleware steps, the original filter, and the rewritten filter sent to the DC

LDAP response bodies are not written, so a domain's search results and schema do not land in the file. The console stays at the normal info level unless you also pass `-v`. A collection prints one info line as each phase starts (`Collecting users`), `Found 20 users` when it finishes, and `users: 14 LDAP searches` for how many LDAP searches that section sent. While either LDAP interval is set, each finished page also adds one line such as `Schema page 4, 300 objects`. Without an interval those page lines stay in the debug log. With both `-v` and `--log-file`, `-v` prints debug to the console as well, and ldapx still omits response bodies so the log file stays readable.

```
bloodhound-ce-python -u USER -p PASS -d domain.local -c DCOnly --log-file bloodhound.log
```

## Guide
This is a full DC-only collection through a local SOCKS5 proxy, with ldapx obfuscation and a short LDAP delay. Use it to check that authentication, rewriting, pacing, and JSON output all work before raising the interval for a larger domain.

1. Install BloodHound.py CE (`pip install .` from this branch). That also downloads ldapx.
2. Start the SOCKS5 proxy and confirm it can open TCP connections to the DC on ports 389, 3268, and 88. For LDAPS, use 636 and 3269 instead and add `--ldapx-ldaps`.
3. Run:

```
bloodhound-ce-python -u USER -p PASS -d domain.local -dc dc01.domain.local -c DCOnly \
  --ldapx-target 10.1.1.1:389 \
  --ldapx-socks socks5://127.0.0.1:1080 \
  --ldapx-filter OGDR --ldapx-attrlist Owp --ldapx-basedn OX \
  --ldap-interval 2s --ldap-jitter 50 \
  --zip --outputprefix domain \
  --log-file domain.log
```

`-dc dc01.domain.local` is only the Kerberos SPN hostname in this mode. The sockets go to `--ldapx-target` through `--ldapx-socks`. `-d domain.local` supplies the base DN (`DC=domain,DC=local`) even when DNS lookups fail.

On Windows, start the tool as `bloodhound-ce-python`. `python bloodhound.py` calls `main()` on import, and the ACL process pool re-imports that file in every worker, so each worker starts another full collection and then crashes. Pass `--disable-pooling` if you launch `bloodhound.py` directly; ACLs are still parsed, in-process.

4. Check the log:
   - `New LDAP searches at least 2s apart, plus 0-50% jitter`
   - `Kerberos traffic will be routed through SOCKS proxy 127.0.0.1:1080`
   - `FilterMiddlewares: [OIDAttribute,Garbage,DblNegBool,ReorderBool]` (and the matching attribute and base-DN lines)
   - `Found N users`, `Found N computers`, `Found N groups`, then `Done in`
5. With `-v`, a rewritten search looks like this. The DC still returns the original objects:

```
Intercepted Search
    Filter: (objectClass=*)
Changed Search
    Filter: (|(!(!(oID.002.005.04.00=*)))(!(!(6fIO0F~=wVOCuB)))(!(!(y3pjxS=Wa8VTi*))))
```

6. Output files are written in the current directory: `domain_<timestamp>_users.json`, `_computers.json`, `_groups.json`, `_domains.json`, `_gpos.json`, `_ous.json`, and `_containers.json`. `--zip` packs those JSON files into `domain_<timestamp>_bloodhound.zip` and removes the loose JSON. Import that zip into BloodHound CE.

Raise `--ldap-interval` once the short run looks right. A 2 second interval is only for a functional check. The runtime estimates in the pacing section are the ones to use on a production domain.

## Limitations
BloodHound.py currently has the following limitations:
- Supports most, but not all BloodHound (SharpHound) features. Currently GPO local groups are not supported, all other collection methods are implemented.
- On Windows, `python bloodhound.py` cannot use the ACL process pool. Use `bloodhound-ce-python`, or pass `--disable-pooling`.

## Docker usage
1. Build container  
```docker build -t bloodhound .```  
2. Run container  
```docker run -v ${PWD}:/bloodhound-data -it bloodhound```  
After that you can run `bloodhound-python` inside the container, all data will be stored in the path from where you start the container.

## Credits
BloodHound.py was originally written by Dirk-jan Mollema, Edwin van Vliet and Matthijs Gielen from [Fox-IT (NCC Group)](https://fox-it.com/). BloodHound.py is currently maintained by Dirk-jan Mollema from [Outsider Security](https://outsidersecurity.nl). The implementation and data model is based on the original tool from [SpecterOps](https://specterops.io). Many thanks to everyone who contributed by testing, submitting issues and pull requests over the years.
