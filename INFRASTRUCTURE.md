# JDY Infrastructure — Enumeration, Pivots & Exclusions

Control-infrastructure analysis for the JDY botnet. The objective here is bounding: not
just listing nodes, but **proving the cluster is closed** using identity-grade anchors,
and excluding co-residency noise with primary evidence.

**TLP:CLEAR** · ICD-203 estimative language · findings tagged **NOVEL / CORROBORATED /
PUBLISHED / EXCLUDED**.

---

## 1. The cluster

JDY's control layer is a small set of relay/C2 nodes sharing a single self-signed TLS
certificate, plus a payload/tasking host. All nodes below are **PUBLISHED** (Lumen
`JDY_6_2026_IOCs.txt`) and **CORROBORATED** by independent enumeration across FOFA,
Netlas, Shodan, and Censys.

### 1.1 Relay / C2 nodes — the `jdyfj` cert cluster

| IP | Hosting | First / Last Seen | Role |
|---|---|---|---|
| `216.173.65.250` | Evoxt | 2026-03-31 / Present | C2 |
| `194.14.217.88` | M247 (RO) | 2026-03-31 / Present | C2 |
| `23.27.120.240` | Evoxt | 2025-04-11 / 2026-03-21 | C2 (aged out) |
| `109.104.154.116` | BrainStorm (NL) | 2025-04-11 / 2026-03-21 | C2 (aged out) |
| `140.82.23.123` | Vultr | historical (2023) | C2 (rotated to Cloudflare) |

**Identity anchor — the `jdyfj` certificate:**

```
SHA-256  2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf
CN       jdyfj
Serial   12362189573138375665
Validity to 2033
First seen 2023-11-14  (matches the KV "JDY" cert swap)
```

This certificate is the **identity-grade pivot** for the whole cluster. The operators
rotate IPs and hosting providers but **do not rotate the keypair** — which is precisely
why the cert pivot keeps resolving the cluster while individual IPs come and go.

### 1.2 Payload / tasking host

| IP | Hosting | Listeners |
|---|---|---|
| `149.248.3.38` | Vultr (LA) | **Platypus** on `:13339`; **Acme Co** Go-TLS listeners on `:9960`–`:9964` |

---

## 2. Bounding the cluster — the pivots

Four pivots were run to test whether any **un-reported** infrastructure exists. All four
returned "already known / bounded."

### 2.1 Certificate pivot (identity-grade) — CORROBORATED, no new node

The correct current Censys field is `host.services.cert.fingerprint_sha256` (the legacy
`services.tls.certificates.leaf_data.fingerprint_sha256` is deprecated and returns
"field not found").

```
host.services.cert.fingerprint_sha256: "2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf"
```

**Result: 2 hosts** — `216.173.65.250` and `194.14.217.88`. Both already in the cluster.
**No sixth node.** This is a live scan, so it shows the cert on hosts Censys has *recently*
scanned; the two it returns are exactly Lumen's two **"Present"** C2 IOCs. The aged-out
pair (`23.27.120.240`, `109.104.154.116`, last-seen 2026-03-21) are down. Three sources
now agree — local enumeration, Censys live, and Lumen IOC dates — that the cluster is
**bounded at the known nodes**.

Independent corroboration: Censys's February 2026 analysis pivots on the **same** cert
hash and the **same** 2023-11-14 swap date, and notes the operators have taken no
meaningful action to conceal their control infrastructure beyond changing hosting
providers — consistent with the "relay layer is expendable" reading below.

### 2.2 Payload-host fingerprint pivot — bounded at one node

The payload host's distinctive combination is **Platypus `:13339` + Acme Co Go-TLS
listeners `:9960`–`:9964`**. The discriminator is the *combination* — Acme Co alone is the
Go standard-library default test certificate and appears on large numbers of unrelated
hosts, so it is noise on its own.

```
# Censys — both listeners on one host
host.services.port: 13339 and host.services.port: 9960
```

**Result: 1 host** — `149.248.3.38`, the already-known payload server. **No sibling
payload/tasking servers exist.** The payload layer is bounded at one node, just as the
relay layer is bounded by the cert.

### 2.3 Lumen IOC re-pull — no change

The live `JDY_6_2026_IOCs.txt` (29 lines) was re-pulled and diffed against the known set:
**no additions.** The only two C2 IOCs marked "Present" are `216.173.65.250` and
`194.14.217.88` — matching the cert pivot exactly.

### 2.4 Bot-fleet enumeration — not passively separable (expected dead end)

The ~1,500 SOHO/IoT bots conduct **quiet SYN reconnaissance**, not loud credential
attacks, and expose **no listening JDY service** (they are clients of the dispatch
service, not servers). They are therefore not cert- or banner-findable and look like
ordinary residential routers. There is no passive selector for the fleet; this confirms a
prior finding rather than opening a new lead.

---

## 3. Why the older lineage IPs no longer count

Censys/DCSO named two earlier control servers from the same cert lineage. Both have since
**rotated away** and been re-leased to other tenants — neither carries the `jdyfj` cert
now:

| IP | 2024 role | Current state | Tag |
|---|---|---|---|
| `45.63.60.39` | JDY node (Censys/DCSO) | Windows RDP/WinRM box, different tenant; forward DNS `alrdydeadinside.mooo.com` (dynamic DNS) | EXCLUDED (rotated) |
| `45.32.174.13` | JDY node (Censys) | Brazilian shared-hosting reseller (`*.gerenciadores.com`) | EXCLUDED (rotated + co-tenancy) |

Their value is **historical confirmation of the rotation pattern**, not live cluster
membership.

---

## 4. Exclusions worked with primary evidence

A recurring trap across China-nexus casework: shared and commodity infrastructure
manufactures false overlaps. Each exclusion below was resolved with primary evidence
(direct query, detonation, architecture check, or the box's own response), not assumption.

| Artifact | Why it appeared linked | Verdict |
|---|---|---|
| NetSupport RAT MSI on `194.14.217.88` | commodity co-tenant, Russian C2 | EXCLUDED — unrelated to JDY |
| Cobalt Strike watermark `987654321` on `140.82.23.123` | trivial sequential default riding crimeware | EXCLUDED |
| `oakenfjrod.ru` infostealer domain (VT relations for `23.27.120.240`) | co-tenant artifact on shared Evoxt VPS | EXCLUDED |
| `*.faucetpot.xyz` (VT relations for `149.248.3.38`) | shared cPanel co-tenant (cpanel/webmail/ftp/mail labels) | EXCLUDED |
| `47.239.105.221` | Finstars fintech agent API (confirmed from the box's own JSON) | EXCLUDED |
| Cloudflare `162.159.36.2` in VT relations | CDN co-residency fan-out | EXCLUDED |
| VT "communicating files" (Windows PE) | a MIPS ELF implant cannot relate to PE samples by arch | EXCLUDED — co-residency fan-out |
| Sandbox detonation PCAP(s) | Windows-guest OS telemetry from an arch-mismatched run | EXCLUDED |

The VT relation noise is collapsed mechanically by [`tools/vt_triage.py`](../tools/vt_triage.py),
which runs an **IOC-first** check (so a real node is never auto-excluded for falling in a
CDN-adjacent prefix), tags CDN/cloud/RFC1918 ranges as co-residency, fails **open** to a
REVIEW worklist for anything unmatched, and now auto-excludes the recurring co-tenant
domains above.

---

## 5. Cross-case exclusion — Salt ↔ Volt

A claimed infrastructure link between **Salt Typhoon / UAT-9244** and **Volt / JDY** was
tested by exact diff. The UAT-9244 cluster uses a different identity anchor entirely —
`CN=8.8.8.8` (leaf `0c7e36683a100a96f695a952cf07052af9a47f5898e1078311fd58c5fdbdecc8`) —
versus JDY's `CN=jdyfj`.

| Test | Result |
|---|---|
| Shared IPs | **0** |
| Shared /16 prefixes | **0** |
| Shared TLS keypair | **none** (`CN=jdyfj` vs `CN=8.8.8.8`) |
| Only convergence | both rent Vultr (commodity hosting) |

**Salt ↔ Volt infrastructure link: EXCLUDED** — no identity-grade overlap. The recurring
appearance of the same co-tenant domains (e.g. `oakenfjrod.ru`) across cases is a
**shared-hosting artifact**, not an operator link.

---

## 6. Structural conclusions

- **Identity-grade anchors beat co-residency.** TLS keypairs and listener fingerprints
  resolve real cluster membership; IP and domain co-residency mostly manufacture false
  overlaps. Both the relay layer (cert) and payload layer (Platypus + Acme Co combo) are
  bounded by identity-grade pivots.
- **Prepositioning stealth lives victim-side.** JDY's relay infrastructure is findable and
  operationally expendable; the operators rotate IPs/hosting freely but never the keypair.
  The durable tradecraft is in the bots and the dispatch design, not the relays.
- **Attribution caps at the capability, not the actor.** JDY is a shared, multi-actor
  reconnaissance ORB of the KV/JDY lineage. Output of shared infrastructure supports a
  *China-nexus reconnaissance capability* framing rather than single-actor ownership;
  attribution to any one actor (including Volt Typhoon specifically) should carry
  appropriately bounded confidence.

---

## 7. Bounding summary

| Pivot | Result | Tag |
|---|---|---|
| Certificate (live) | 2 hosts, both known | CORROBORATED — bounded |
| Payload-host fingerprint | 1 host, the known one; no siblings | CORROBORATED — bounded |
| Lumen IOC re-pull | no change since last pull | CORROBORATED |
| Bot fleet | not passively separable | (expected) |
| Older lineage IPs | rotated away | EXCLUDED |
| Salt ↔ Volt link | no identity-grade overlap | EXCLUDED |

The infrastructure is **fully enumerated and bounded**. No un-reported node carries the
`jdyfj` keypair or the payload-host fingerprint as of analysis.
