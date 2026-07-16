# Security Layer - Overview

A short, visual tour of the protections added to the **secured** simulator. Every idea is shown with a diagram and a few lines of simplified pseudocode, not the real C.

The goal here is the *big picture*, not every detail.

---

## Why anything was needed

A car's internal network (the **CAN bus**) was built for reliability, not
security. Two consequences:

- **Any device can send any message, and no message proves who sent it.**
  → an attacker can fake the speed, unlock doors, blink the turn signals.
- **The maintenance protocol (UDS) had weak locks.**
  → an attacker could brute-force its "security unlock" and reach hidden commands.

The secured build adds **two layers** to close these. The unsecured build keeps
the holes on purpose, so the same attacks can be tried on both and compared.

```mermaid
flowchart LR
    ATK[Attacker<br/>on the bus]:::bad
    SND[Control panel<br/>legit sender]:::good
    BUS((CAN bus))

    SND -- signed frames --> BUS
    ATK -- fake / replayed frames --> BUS
    ATK -- diagnostic abuse --> BUS

    BUS --> RCV[Instrument cluster<br/>receiver]

    subgraph L1[LAYER 1 - SecOC]
        V{Signature valid<br/>and fresh?}
    end
    subgraph L2[LAYER 2 - UDS hardening]
        G{Crypto unlock +<br/>lockout + rate limit}
    end

    RCV -- driving messages --> V
    RCV -- diagnostics --> G

    V -- yes --> OK[Update dashboard]:::good
    V -- no --> DROP[Drop frame]:::bad
    G -- pass --> SVC[Allow service]:::good
    G -- fail --> NRC[Reject]:::bad

    classDef bad  fill:#7b1a1a,stroke:#e74c3c,color:#ffffff;
    classDef good fill:#1a4a2a,stroke:#2ecc71,color:#ffffff;
```

*(Diagram source: [`diagrams/overview.mmd`](diagrams/overview.mmd).)*

---

## Layer 1 - Messages that prove who sent them (SecOC)

**Idea.** Treat each message like a postcard and add a tamper-proof **wax seal**
plus a **page number**:

- **Seal (a MAC):** a short code computed from the message *and* a secret key
  shared only by the real computers. No key → no valid seal → **forgeries are
  rejected**.
- **Page number (a counter):** goes up by one each time. A recorded message
  played back later carries an old number → **replays are rejected**.

```mermaid
sequenceDiagram
    participant S as Sender
    participant B as CAN bus
    participant R as Receiver
    participant A as Attacker

    S->>S: counter = counter + 1
    S->>S: mac = CMAC(key, id + payload + counter)
    S->>B: payload + counter + mac
    B->>R: payload + counter + mac
    R->>R: recompute mac, check counter is newer
    R-->>R: valid & fresh -> update dashboard

    A->>B: forged frame (no real key)
    B->>R: forged frame
    R-->>R: mac mismatch -> DROP

    A->>B: replay of an old frame
    B->>R: replay
    R-->>R: stale counter -> DROP
```

*(Diagram source: [`diagrams/block1-secoc.mmd`](diagrams/block1-secoc.mmd).)*

**Sending** (every real message gets stamped):

```text
counter = counter + 1
mac     = CMAC(secret_key, id + payload + counter)
send(payload + counter + mac)
```

**Receiving** (verify, or throw it away):

```text
expected = CMAC(secret_key, id + payload + counter)

if expected != received_mac:      drop()   # forged
elif counter <= last_seen[id]:    drop()   # replayed
else:
    last_seen[id] = counter
    accept()                               # safe to use
```

> **One honest limit:** this proves *who* sent a message, it does **not** hide
> it. Anyone can still listen on the bus - exactly like real cars, which don't
> encrypt CAN. So reading values (e.g. the VIN) still works; *forging* them does
> not.

---

## Layer 2 - Hardening the diagnostic "garage door" (UDS)

The maintenance protocol is a second way in. Layer 2 adds four gates, all using
standard ISO 14229 (UDS) mechanisms. Every diagnostic request must pass them:

```mermaid
flowchart TD
    REQ[Diagnostic request] --> SVC{Which service?}

    SVC -- Routine --> RL{Arrived < 250 ms<br/>after last one?}
    RL -- yes --> R21[Reject 0x21<br/>busy / slow down]:::bad
    RL -- no --> SECRET{Secret routine?}
    SECRET -- yes --> UNL{SecurityAccess<br/>passed?}
    UNL -- no --> R33[Reject 0x33<br/>access denied]:::bad
    UNL -- yes --> RUN[Run routine]:::good
    SECRET -- no --> RUN

    SVC -- SecurityAccess --> LCK{Locked out?}
    LCK -- yes --> R37[Reject 0x37<br/>wait]:::bad
    LCK -- no --> KEY{Crypto key<br/>correct?}
    KEY -- yes --> OPEN[Unlock]:::good
    KEY -- no --> R35[Reject 0x35/0x36<br/>+ start lockout]:::bad

    classDef bad  fill:#7b1a1a,stroke:#e74c3c,color:#ffffff;
    classDef good fill:#1a4a2a,stroke:#2ecc71,color:#ffffff;
```

*(Diagram source: [`diagrams/block2-gates.mmd`](diagrams/block2-gates.mmd).)*

### A · An unlock that can't be guessed

The "SecurityAccess" unlock is a challenge: the ECU sends a random **seed**, the
tool must reply with the matching **key**.

- *Before:* the key was a simple public rule (`seed XOR fixed bytes`) - cracked
  in a few dozen tries.
- *After:* the key is `CMAC(secret_key, seed)`. It depends on a secret key **and**
  a fresh random seed, so there is no rule to discover and no way to compute it
  without the key.

```mermaid
sequenceDiagram
    participant T as Tester / Attacker
    participant E as ECU (cluster)

    T->>E: request seed (0x27 01)
    E->>T: random 4-byte seed
    Note over E: correct key = CMAC(secret_key, seed)<br/>cannot be guessed without the key

    T->>E: send key (0x27 02)
    alt key correct
        E->>T: unlocked
    else wrong key
        E->>T: invalidKey 0x35 + forced wait
        Note over E: 3 wrong in a row -> long lockout 0x36<br/>not cleared by reset / session change
    end
```

*(Diagram source: [`diagrams/block2-securityaccess.mmd`](diagrams/block2-securityaccess.mmd).)*

### B · Slow down and lock out guessing

Wrong guesses cost time, so automated scripts stall:

```text
if locked_until > now:        reject(0x37)            # still timed out
elif key == expected_key:     unlock(); fails = 0
else:
    fails = fails + 1
    locked_until = now + (fails >= 3 ? LONG : SHORT)   # 10 s vs 1 s
    reject(fails >= 3 ? 0x36 : 0x35)
```

The counter and lockout **survive an ECU reset or session change**, so an
attacker can't wipe the penalty - just like a real ECU.

### C · Guard the hidden command

A hidden privileged "routine" used to run for anyone in the diagnostic session.
Now it requires the unlock above first:

```text
if routine == SECRET and not security_unlocked:
    reject(0x33)            # must pass SecurityAccess first
```

### D · Rate-limit probing

A routine is a 3-byte number (~16.7 million possibilities), so attackers scan for
hidden ones. We cap the speed:

```text
if now - last_routine_time < 250 ms:
    reject(0x21)            # busy, slow down
last_routine_time = now
```

At one allowed try per 250 ms, a full scan goes from *minutes* to *weeks*.

---

## Before vs after, at a glance

| Attack | Unsecured | Secured | Layer |
|--------|-----------|---------|-------|
| Fake speed / unlock doors / fake blinker | works | **dropped** (bad seal) | 1 |
| Replay a recorded message | works | **dropped** (old counter) | 1 |
| Just listen / read the VIN | works | **still works** (by design) | - |
| Brute-force the diagnostic unlock | dozens of tries | **infeasible** (crypto + lockout) | 2A/2B |
| Wipe the lockout with a reset | n/a | **doesn't work** | 2B |
| Scan for the hidden routine | found fast | **blocked** (needs unlock + throttled) | 2C/2D |

---

## Two things this does NOT do

1. **It does not make traffic private.** An eavesdropper can still read the bus.
2. **Everything depends on one secret key.** If the key leaks, both layers fall.
   In this lab the key is kept simple; a real car stores it in secure hardware.

> Want the exact wire format, NRC codes, key bytes, and build flags? That level
> of detail lives in [`../SECURITY.md`](../SECURITY.md).
