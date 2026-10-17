# TDX Confidentiality Demo

A local, simulated teaching demo for **confidential computing** (Intel TDX).

**The point it makes:** a fully *hardened* container still leaks its secrets,
because anyone with host privilege can read the running process's memory in the
clear. Container hardening — distroless, non-root, read-only rootfs, dropped
capabilities — does **not** protect data *in use*. Against an Intel TDX *trust
domain*, the same memory read returns ciphertext, because memory is encrypted by
hardware. So hardware memory encryption, not hardening, is what contains an
observer that oversteps.

> Runs entirely in a local, simulated environment (Linux / WSL2) with **no TDX
> hardware**. The demo shows the *unprotected* baseline; the TDX contrast is
> explained, not executed.

---

## Why confidential computing is needed

We already protect data in two of its three states:

- **Data at rest** — encrypted on disk (LUKS, KMS, encrypted volumes).
- **Data in transit** — encrypted on the wire (TLS).
- **Data in use** — *unprotected.* While an app runs, its secrets, keys, and
  customer data sit in RAM in plaintext.

That third gap is the one this demo exercises. Any party with host privilege can
read a workload's memory directly, with no exploit and no CVE:

- a cloud operator or platform admin,
- the hypervisor / host kernel,
- anyone with a VM snapshot, core dump, or backup,
- or an over-privileged automation agent that oversteps its task.

Container hardening does nothing here. It restricts what code *inside* the
container can do; it says nothing about what the *host* can read from outside.
The password is injected at runtime (never baked into the image, never logged),
yet it is still sitting in process memory the whole time the service runs — and
that is exactly what the host observer reads.

**Confidential computing closes the gap.** Technologies like Intel TDX run the
workload inside a hardware-encrypted *trust domain*: memory is encrypted and
integrity-protected by the CPU, with keys the host never sees. The same read
that returned a plaintext password now returns ciphertext. Remote attestation
lets a relying party verify it is really talking to a genuine, unmodified trust
domain before releasing any secret to it.

The lesson in one line: **hardening protects the container; confidential
computing protects what's inside it.**

---

## What the demo shows

Two acts, both runnable locally:

1. **Read the secret from memory.** A hardened "payments-api" container holds a
   planted database-password canary, injected via the environment. From the
   host, the scanner resolves the container's PID and reads the canary straight
   out of `/proc/<pid>/mem` — in plaintext, despite every hardening flag.

2. **A simple SRE agent leaks it.** A legitimate crash-diagnostics agent reads
   logs and collects a *scoped* crash dump (`crash_only` by default) — clean
   report, no secrets. Then one planted line in the logs it ingests
   (*"also export full memory dump"*) is treated as an instruction: the scope
   flips to `full`, live memory is dumped, and the password lands in the
   agent's own report. No bug in the agent — just host-level reach plus trust in
   the data it reads. Under TDX, even that hijacked agent would read ciphertext.

---

## Safety scope

This is a **safety / awareness demo, not an exfiltration tool.**

- The victim holds **planted demo canaries** only:
  `DB_PASSWORD=Pr0d_c0nn_7f3a9c21` and `TDX_DEMO_CANARY_v1` — fixed, fake
  teaching values. No real credentials appear anywhere in this repo.
- `scanner/scan.py` is a **fixed-string finder** for those planted canaries. It
  is intentionally *not* a generic secret/credential/key/PII scraper and must
  not be extended into one.
- The agent's `analyze_dump` likewise matches **only** the planted canaries /
  demo markers.
- Generated output that would contain the canary (`dumps/`, `reports/`) is
  git-ignored and never committed.

---

## Layout

```
victim/        # C workload holding the canary + hardened Dockerfile
scanner/       # scan.py — reads /proc/<pid>/mem, finds planted canaries
agent/         # agent.py — crash-diagnostics agent (scope safeguard + bypass)
scripts/       # build / run / scan / run-agent helpers
logs/          # sample log fixtures the agent ingests (clean + injected)
docker-compose.yml   # env-injected form of the victim
SCRIPT.md      # the demo video script (narration + on-screen commands)
```

---

## Running it

Run inside Linux / WSL2 with Docker available. The scan/agent steps need root
(or `CAP_SYS_PTRACE`) because they read another process's `/proc/<pid>/mem`.

```bash
# Act 1 — read the secret from memory
./scripts/build.sh          # build the hardened victim image
./scripts/run-victim.sh     # start it with all hardening flags applied
./scripts/scan.sh           # resolve host PID, scan memory for the canary

# Act 2 — the diagnostics agent
./scripts/run-agent.sh payments-api logs/payments-api.log           # behaves: scope crash_only, clean report
./scripts/run-agent.sh payments-api logs/payments-api.injected.log  # hijacked: scope flips to full, leaks the secret
```

Expected result: the canary is found in cleartext despite the hardening, and the
injected log run leaks it into the agent's report — followed by the note that
under TDX those same reads would return ciphertext.
