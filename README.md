# CSC380_TOTP

TOTP (RFC 6238) generator, verifier and experiments studying how the acceptance
window trades off usability (clock-offset tolerance) against security.

| Part | Files |
|------|-------|
| 1 — Generator | `totp.h`, `totp.cpp`, `test_totp.cpp` |
| 2 — Verifier | `verifier.h`, `verifier.cpp` |
| 3 — Experiments | `experiments.cpp` → `results.csv` |
| 4 — Demo & integration | `main.cpp`, `Makefile`, results summary |

## Build

Requires a C++17 compiler and Crypto++ (`brew install cryptopp` on macOS,
`sudo apt install libcrypto++-dev` on Ubuntu).

```bash
make            # builds test_totp, experiments (and totp_demo once main.cpp exists)
make test       # RFC 6238 vectors + verifier checks
make results    # regenerates results.csv and prints a summary
make clean
```

## Experiment 1 — window vs. clock offset (`results.csv`)

The server verifies at a fixed time; the client's clock is off by
`clock_offset_s` seconds (−90…+90, step 5). Repeated for `window` 0 and 1 and
for several positions inside the server's 30-second step.

CSV columns:

| column | meaning |
|---|---|
| `window` | 0 = current step only, 1 = previous + current + next |
| `position_in_step` | seconds into the server's 30 s step (0–29) |
| `clock_offset_s` | client clock minus server clock, in seconds |
| `accepted` | 1 if the legitimate code was accepted, else 0 |
| `matched_offset` | step that matched (−1, 0, +1); empty if rejected |
| `reason` | verifier reason: `ok`, `no match`, `malformed`, `reused`, `locked` |
| `distinct_valid_codes` | how many different codes the verifier accepts at that moment |

Preliminary result: with window = 0 a legitimate code is accepted only when the
offset keeps the client inside the server's current step (0–29 s of tolerance,
depending on position). With window = 1 every offset within ±30 s is accepted,
and partially up to ±59 s, at the cost of 3 valid codes instead of 1.

Guessing (attempt limit) and reuse experiments are scheduled for Nov 23–29 and
will write their own CSV files; `results.csv` keeps the format above.

