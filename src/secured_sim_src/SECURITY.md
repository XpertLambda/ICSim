# Secured Simulator - Security Layers Reference

This document describes **everything** added to the secured build of the ICSim
simulator (`src/secured_sim_src/`) on top of the original (unsecured) simulator.
It is written so it can be lifted directly into the student guide for the
"security layer" section.

The secured simulator is byte-compatible with the unsecured one for normal
driving, but it **authenticates its CAN traffic** and **hardens its UDS
diagnostics** so that the attacks students perform against the unsecured sim are
detected and rejected.

> **Two-stage pedagogy.** Students first attack the *unsecured* sim
> (`src/sim_src/`) and succeed. They then run the *secured* sim
> (`icsim-start --secure`) and re-run the exact same attacks - and watch them
> fail. The contrast is the lesson.

---

## Threat model

Classic CAN has **no authentication**: any node can transmit any arbitration
ID, and a frame never proves who sent it. An attacker with bus access can
therefore:

1. **Spoof / inject** signal frames (fake speed, unlock doors, blink turn
   signals, toggle warning lights).
2. **Replay** captured frames.
3. **Sniff** all traffic (read VIN, observe everything).
4. **Abuse diagnostics (UDS)**: escalate sessions, brute-force SecurityAccess,
   enumerate hidden RoutineControl services.

The secured sim closes **1, 2, and 4**. It does **not** (and cannot) close
**3** - see [Limitations](#limitations).

There are two independent defense layers:

| Layer | Protects | Mechanism |
|-------|----------|-----------|
| **1. SecOC** | broadcast signal frames | per-message MAC + freshness counter |
| **2. UDS hardening** | diagnostic services | strong SecurityAccess + rate limiting + authorization gating |

---

## Layer 1 - SecOC message authentication (signal frames)

**AUTOSAR-style Secure Onboard Communication.** Every signal the controller
legitimately broadcasts is signed; the instrument cluster verifies the
signature and **drops anything that fails** ("verify-or-drop").

**Files:** `CAN/secoc.h`, `CAN/secoc.c`, with calls wired into `CAN/controls.c`
(sender) and `CAN/icsim.c` (receiver).

### Attacks it stops

- **Frame injection / spoofing** - a forged `0x244` (speed), `0x19B` (doors),
  `0x188` (turn), etc. has no valid MAC, so the cluster ignores it.
- **Replay** - a captured-and-resent frame carries an old freshness counter and
  is rejected as stale.

### Protected arbitration IDs

| CAN ID | Signal |
|--------|--------|
| `0x007` | control / shared-data channel |
| `0x188` | turn signal |
| `0x19B` | door locks |
| `0x244` | speed |
| `0x39C` | luminosity |
| `0x42A` | warning |

Any other ID is "not protected" and passes through untouched (diagnostics on
`0x7E0`/`0x7E8` are handled by Layer 2, not SecOC).

### Wire format (CAN FD, 20-byte frame)

The signed frame is a **CAN FD** frame. The original 8-byte payload keeps the
same byte offsets, so existing decoders still work; the MAC and counter are
appended in a trailer:

```
 byte:  0 .. 7      8 .. 11        12 .. 19
       [payload]  [freshness FV]  [truncated MAC]
                   uint32, BE      AES-128-CMAC(...)[0..7]
```

- `data[0..7]` - original signal payload (unchanged offsets).
- `data[8..11]` - **Freshness Value (FV)**: a monotonic 32-bit counter,
  big-endian. Each ID has its own counter.
- `data[12..19]` - **MAC**: the first 8 bytes of
  `AES-128-CMAC( key, id ‖ data[0..7] ‖ FV )`.

`SECOC_FRAME_LEN = 20` is a valid CAN FD DLC.

### Algorithm

- **Primitive:** AES-128-CMAC (the exact AUTOSAR SecOC MAC profile), via
  OpenSSL `EVP_MAC` / `libcrypto`.
- **MAC input:** `id (2 bytes, big-endian 11-bit) ‖ data[0..7] ‖ FV (4 bytes, big-endian)` = 14 bytes.
- **Sender** (`secoc_sign`): increments that ID's counter, computes the MAC over
  the input, writes FV + MAC into the trailer, sets the frame length to 20.
- **Receiver** (`secoc_verify`): recomputes the MAC, compares it in
  **constant time** (`CRYPTO_memcmp`, so a wrong MAC leaks no timing about the
  key), and additionally requires the FV to be **strictly greater** than the
  last accepted FV for that ID. A frame that is too short, has a bad MAC, or has
  a stale/replayed counter is rejected; the receiver logs
  `[SecOC] dropped unauthenticated/replayed frame 0x###`.

### Key management

- A single 128-bit key is shared by the controller (sender) and the cluster
  (receiver). In the lab it is **compiled into both** (`SECOC_KEY` in
  `secoc.c`). The attacker tooling does **not** have it, so it cannot forge a
  valid MAC.
- **In a real vehicle** this key would be provisioned per ECU and stored in an
  HSM / secure flash, never in source. Rotating it is a one-line change in
  `secoc.c`.

---

## Layer 2 - UDS diagnostic hardening

The unsecured sim's diagnostics could be defeated by the attacker tooling:
free session escalation, a brute-forceable SecurityAccess, and an enumerable
hidden routine. Layer 2 closes all of these in `CAN/icsim.c`, with tuning
constants and new negative-response codes (NRCs) defined in `CAN/data.h`.

These are standard ISO 14229 (UDS) mechanisms - the same ones real ECUs use.

### 2a - Strong SecurityAccess crypto (service 0x27)

**Before:** the seed was 2 random bytes and the expected key was simply
`seed XOR {0x35, 0x30}` (the last two characters of the VIN). The attacker
brute-forcer guessed this linear scheme in a few dozen tries.

**After:**

- The seed is **4 random bytes**.
- The expected key is `AES-128-CMAC( SecOC_key, seed )` truncated to **4 bytes**
  (function `secoc_sec_response()` in `secoc.c`, reusing the SecOC key).
- The submitted key is compared in constant time.

Because the key is a **keyed MAC** and the attacker does not hold the key, the
response to a fresh random seed **cannot be computed or predicted**. The linear
`seed XOR const` weakness is gone.

> **Consequence (intended):** SecurityAccess is **not solvable from the bus** on
> the secured sim. This is deliberate - the secured sim is the "locked down"
> reference. There is no hidden algorithm for students to discover here; the
> learning happens on the unsecured sim.

### 2b - Anti-brute-force throttling

Even though the crypto already makes guessing infeasible, the secured sim adds
the ISO 14229 timing defenses so that **automated key-guessing scripts visibly
stall**:

- After **each** wrong key: a mandatory delay during which 0x27 returns
  `requiredTimeDelayNotExpired` (NRC **0x37**).
- After **`SEC_MAX_ATTEMPTS`** consecutive wrong keys: a longer lockout, and
  0x27 returns `exceededNumberOfAttempts` (NRC **0x36**).
- A successful key resets the failure counter.

**Reset-resistance:** the failure counter and lockout deadline
(`secFailCount`, `secLockUntil`) are **not** cleared by a session change or ECU
reset. An attacker therefore cannot wipe the lockout by sending
`DiagnosticSessionControl 0x10 01` or an ECU reset - mirroring real ECUs that
persist the attempt counter in non-volatile memory.

### 2c - Authorization gating of the secret routine

**Before:** the hidden RoutineControl `0x31 41 22` only required the (freely
entered) extended session `0x02`, so anyone could trigger it.

**After:** `0x31 41 22` requires that **SecurityAccess has succeeded in the
current session** (`secretSessionFound == 1`). Otherwise it returns
`securityAccessDenied` (NRC **0x33**). Entering session 2 directly with
`0x10 02` no longer unlocks it; the only path is through the (now uncrackable)
SecurityAccess.

### 2d - RoutineControl rate limiting

To defeat the exhaustive `0x31 XX YY ZZ` scanner:

- RoutineControl requests arriving **closer together than
  `ROUTINE_MIN_INTERVAL_MS`** are rejected with `busyRepeatRequest` (NRC
  **0x21**).
- A flood keeps resetting the interval timer, so it stays blocked. A legitimate
  tester sending occasional routines is unaffected.

At the configured 250 ms minimum, a full 3-byte (16.7 M-combination) scan would
take roughly **48 days** instead of minutes.

### 2e - VIN read stays open (by design)

`ReadDataByIdentifier` / mode `09 02` (VIN) remains freely readable. VIN is
**public information** on real vehicles (visible through the windshield, on OBD
mode 09); locking it would be unrealistic, so it is intentionally left open.

---

## Attack-by-attack: before vs after

| Attack (attacker tooling) | Unsecured sim | Secured sim |
|---------------------------|---------------|-------------|
| Spoof speed `0x244`, unlock doors `0x19B`, fake turn `0x188`, etc. | dashboard reacts | **dropped** - no valid MAC (`[SecOC] dropped …`) |
| Replay a captured signal frame | dashboard reacts | **dropped** - stale freshness counter |
| Sniff bus / read VIN | works | **still works** (SecOC ≠ confidentiality; VIN public by design) |
| `escalate()` → programming session `0x10 03` | granted | granted, but the session alone unlocks nothing |
| SecurityAccess `0x27` key brute-force | ~dozens of guesses succeed | **impossible** - CMAC key + NRC 0x37/0x36 lockout |
| `routine_scanner.py` finds `0x31 41 22` | works in session 2 | NRC **0x33** (needs 0x27) **and** throttled by NRC **0x21** |

---

## Negative response codes (NRCs) used

| NRC | Name | Where |
|-----|------|-------|
| `0x21` | busyRepeatRequest | RoutineControl rate limit |
| `0x33` | securityAccessDenied | secret routine without prior 0x27 |
| `0x35` | invalidKey | wrong SecurityAccess key |
| `0x36` | exceededNumberOfAttempts | SecurityAccess lockout (after N fails) |
| `0x37` | requiredTimeDelayNotExpired | SecurityAccess delay/lockout active |

---

## Configuration / tuning reference

All tunables live in `CAN/data.h`:

| Constant | Default | Meaning |
|----------|---------|---------|
| `SEC_SEED_LEN` | `4` | bytes of SecurityAccess seed and expected key |
| `SEC_MAX_ATTEMPTS` | `3` | consecutive bad keys before lockout |
| `SEC_DELAY_MS` | `1000` | mandatory delay after each bad key (ms) |
| `SEC_LOCK_MS` | `10000` | lockout duration after `SEC_MAX_ATTEMPTS` fails (ms) |
| `ROUTINE_MIN_INTERVAL_MS` | `250` | minimum spacing between RoutineControl requests (ms) |

The SecOC key is `SECOC_KEY` in `CAN/secoc.c`. SecOC trailer layout constants
(`SECOC_FV_OFFSET`, `SECOC_MAC_OFFSET`, `SECOC_MAC_LEN`, `SECOC_FRAME_LEN`) are
in `CAN/secoc.h`.

---

## Files in the secured build

| File | Role |
|------|------|
| `CAN/secoc.h` | SecOC + SecurityAccess-key API and wire-format documentation |
| `CAN/secoc.c` | AES-128-CMAC implementation; `secoc_sign`, `secoc_verify`, `secoc_sec_response` |
| `CAN/controls.c` | sender - signs each protected frame via `secoc_sign()` |
| `CAN/icsim.c` | receiver - `secoc_verify()` gate + all UDS hardening (Layer 2) |
| `CAN/data.h` | UDS NRC defines + Layer 2 tuning constants |
| `CAN/Makefile` | builds with `-lcrypto` (OpenSSL) |

---

## Build & run

```sh
# Build locally
cd src/secured_sim_src/CAN
make            # links icsim + controls against -lSDL2 -lSDL2_image -lcrypto

# Run the secured sim in the lab container
icsim-start --secure            # SecOC + UDS hardening enabled
icsim-start --secure --noise    # same, with background traffic
```

In Docker the secured sim is compiled into `/opt/CH-Workshop-secured/CAN`
(needs the `libssl-dev` package, already in the image). The build context is the
repo root so the Dockerfile can `COPY src/secured_sim_src`.

---

## Limitations

- **No confidentiality.** CAN is a broadcast bus. SecOC provides integrity and
  authenticity, not secrecy - an attacker can still **sniff** every frame. Real
  cars do not encrypt CAN either. VIN and all signal *values* remain observable;
  what changes is that an attacker can no longer **forge** them.
- **Security depends on key secrecy.** If an attacker extracts `SECOC_KEY` from
  a binary, both SecOC and the hardened SecurityAccess fall. In the lab the key
  is compiled in for simplicity; production keeps it in an HSM.
- **SecurityAccess is intentionally uncrackable here.** The secured sim is the
  reference "after" state, not a second challenge. If a solvable-but-harder
  challenge is wanted, it needs a different design (e.g. a key derivable from
  discoverable data).
