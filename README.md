# ICSim - IoV / CAN Bus Security Lab

A hands-on Internet-of-Vehicles security lab built around the **Instrument
Cluster Simulator (ICSim)**. It pairs an intentionally **vulnerable** CAN
simulator with a **secured** build so the same attacks can be run against both
and the difference observed directly.

The project bundles:

| Component | Path | What it is |
|-----------|------|------------|
| Vulnerable simulator | `src/sim_src/` | The attack target - pristine upstream ICSim / Barbhack fork (see *Attribution*). |
| Secured simulator | `src/secured_sim_src/` | Same simulator hardened with **SecOC** message authentication (AES-128-CMAC) and **UDS** hardening. See `src/secured_sim_src/SECURITY.md`. |
| CAN injection tool | `scripts/automation-scripts/` | Interactive attacker tooling: frame injection, UDS client, SecurityAccess / RoutineControl scanners. |
| Web lab | `web/` | Static guided lab (no backend). |
| Setup / packaging | `_set/` | Host setup script and Docker workshop image build. **Note:** kept local-only (git-ignored via `_*`), so it is not present in a fresh clone. |

## Quick start

```sh
# 1. Bring up a virtual CAN interface
cd src/secured_sim_src/CAN
sudo ./setup_vcan.sh                  # creates vcan0

# 2. Build (needs SDL2, SDL2_image, libssl-dev, can-utils)
make                                  # -> ./icsim and ./controls

# 3. Run, in two terminals
./icsim vcan0                         # the instrument cluster
./controls vcan0                      # the control panel
```

The vulnerable build (`src/sim_src/CAN`) builds and runs the same way, without
the `-lcrypto` dependency.

## License

This project is licensed under the GNU GPL v3.0. See [LICENSE](LICENSE).

This repository is distributed under the **GNU General Public License v3.0 or
later** (`LICENSE`), consistent with its GPL-licensed upstream components.

- Original work in this repository - the SecOC security layer, the UDS
  hardening, the CAN injection tooling, the IDS, the web lab and the setup /
  packaging - is **Copyright (c) 2026 Xpert** and licensed GPL-3.0-or-later.
- It incorporates and redistributes GPL-licensed upstream code; see
  **Attribution** below and `THIRD_PARTY_NOTICES.md`.

If you redistribute this project (source or binaries), you must meet the GPL
obligations, including providing corresponding source and **preserving all
copyright and license notices**.

## Attribution

The simulator is derived from **ICSim**, originally by Craig Smith / Open
Garages, via the **Barbhack "CH-Workshop"** fork by phil-eqtech:

- ICSim (upstream): https://github.com/zombieCraig/ICSim - © 2014 Open Garages,
  Craig Smith. Original `(c)` notices are preserved in the source headers.
- Barbhack CH-Workshop fork (new GUI, UDS, challenges, art): phil-eqtech.

`src/sim_src/` is kept as the **unmodified** upstream reference.
`src/secured_sim_src/` is a **derivative** of it; the modifications are
documented in `THIRD_PARTY_NOTICES.md` and `src/secured_sim_src/SECURITY.md`.

## Warranty

This project is provided "as is", without warranty of any kind, to the extent
permitted by applicable law. It is intended for education and authorized
security testing only.
