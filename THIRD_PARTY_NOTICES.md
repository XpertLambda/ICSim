# Third-Party Notices

This repository includes third-party software. Its license and copyright
notices are preserved in the original source files and license documents.

## ICSim (Instrument Cluster Simulator)

- **Upstream:** https://github.com/zombieCraig/ICSim
- **Original copyright:** © 2014 Open Garages - Craig Smith <craig@theialabs.com>
- **Intermediate fork:** Barbhack "CH-Workshop" by phil-eqtech (new GUI, UDS
  diagnostics, challenge/scoring system, artwork).
- **License:** GNU General Public License v3.0 or later (GPL-3.0-or-later)
- **License files:** `src/sim_src/LICENSE`, `src/sim_src/CAN/LICENSE`,
  `src/secured_sim_src/LICENSE`, `src/secured_sim_src/CAN/LICENSE`

### Distribution in this repository

- `src/sim_src/` - the **unmodified** upstream simulator, redistributed
  verbatim as the lab's attack target. Original copyright and license notices
  are kept intact.
- `src/secured_sim_src/` - a **derivative work** of the simulator. The original
  Open Garages / Craig Smith and phil-eqtech notices are preserved in the file
  headers; the additions for this secured build are
  © 2026 Xpert and are documented below and in
  `src/secured_sim_src/SECURITY.md`.

### Modifications in `src/secured_sim_src/` relative to upstream

- Added `CAN/secoc.c` / `CAN/secoc.h`: AUTOSAR-style SecOC message
  authentication (AES-128-CMAC + freshness counter).
- `CAN/controls.c`: signs every transmitted protected frame (`secoc_sign`);
  diagnostic frames are sent over the bound socket instead of shelling out.
- `CAN/icsim.c`: verify-or-drop SecOC gate; UDS hardening (CMAC-based
  SecurityAccess, anti-brute-force lockout, RoutineControl rate limiting,
  authorization gating of the secret routine).
- `CAN/data.h`: additional UDS negative-response codes and tuning constants.
- `CAN/Makefile`: links against OpenSSL `-lcrypto`.
- Bug fixes carried in this build (also applicable upstream): corrected
  `getopt` option string, operator-precedence fix in the control-channel
  integrity check, no-op statement fixes, bounded interface-name copies, and
  a NULL check on the seed file.

## can-utils

The simulator and tooling invoke `can-utils` (`canplayer`, `cansend`,
`isotpsend`/`isotprecv`) at runtime. These are not redistributed here; install
them via your distribution. can-utils is licensed under GPL-2.0 / BSD.
