# FFmpeg Supply Chain Security Review

**Date:** 2026-04-07
**Period analyzed:** Commits after 2026-02-15
**Total commits in period:** 50 (non-merge)
**Total unique authors:** 16

## Methodology

Identified all authors whose first-ever commit to the repository falls on or
after 2026-02-15. Examined every commit from these new contributors for:
1. Changes to security-critical code (parsers, decoders, memory management, crypto)
2. "Security fixes" that might introduce worse vulnerabilities
3. Suspicious build system or test infrastructure changes
4. Trust-escalation patterns (e.g., adding oneself to CODEOWNERS)

---

## New Contributors Identified (0 commits before 2026-02-15)

| Author | Email | Commits | Nature |
|--------|-------|---------|--------|
| Hankang Li | hankang201222@gmail.com | 1 | Integer overflow fix in libswscale |
| Dana Feng | danafeng@berkeley.edu / danaf@twosigma.com | 3 | mpdecimate filter fix + tests + CODEOWNERS |
| Marcos Ashton | marcosashiglesias@gmail.com | 3 | FATE tests (mathematics, samplefmt, rc4) |
| Sankalpa Sarkar | sankalpasarkar68@gmail.com | 2 | FATE tests (timecode, hlsenc) |

**Note:** Zhao Zhili (zhilizhao@tencent.com, 1 commit) initially appeared new but
has 609 prior commits under quinkblack@foxmail.com. Not a new contributor.

---

## Detailed Analysis of Security-Relevant Commits

### 1. Hankang Li — `e33b3962` — "fix signed integer overflow in color conversion arithmetic"

**Files:** `libswscale/input.c`, `libswscale/output.c`
**Signed-off-by:** Michael Niedermayer (29,850 prior commits)

**What it does:** Converts signed integer arithmetic in RGB↔YUV color
conversion to unsigned arithmetic, then casts back to signed before right
shift. The pattern used:
```c
// Before (undefined behavior on overflow):
dst[i] = (ry*r + gy*g + by*b + offset) >> shift;

// After (well-defined):
dst[i] = (int)((unsigned)ry*r + (unsigned)gy*g + (unsigned)by*b + offset) >> shift;
```

In `output.c`, also casts U/V chroma values to `SUINT` (FFmpeg's macro for
`unsigned` in production, `int` in debug/checked builds) before multiplying
with color conversion coefficients.

**Risk assessment: LOW**

- Uses the established `SUINT`/`(unsigned)` pattern that FFmpeg employs
  project-wide for exactly this purpose (`libavutil/internal.h:130-138`).
- Signed-off by Michael Niedermayer, who made **four additional** integer
  overflow fixes in the same file in the same period (commits `3b98e29d`,
  `1e63151`, `a5918002`, `86ddc8b4`), all using the same technique.
- The fix is incomplete (e.g., lines 1543-1544 of `output.c` have the same
  unfixed pattern), which is more consistent with an organic, partial fix
  than a carefully targeted attack.
- The numerical output is identical on all two's-complement hardware with
  arithmetic right shift (i.e., every platform FFmpeg targets).
- No new code paths, no new allocations, no new control flow. Pure
  arithmetic type changes.

**Verdict: Appears legitimate.** Part of an ongoing series of
fuzzer-discovered integer overflow fixes.

---

### 2. Dana Feng — `63822ae2` — "Fix keep option logic for keep > 0"

**File:** `libavfilter/vf_mpdecimate.c`

**What it does:** Refactors the mpdecimate video filter's frame drop/keep
decision logic. Introduces a `DecimateResult` enum to distinguish three
outcomes (DROP, KEEP_UPDATE, KEEP_NO_UPDATE) and rewrites the filter to
always perform the similarity check before evaluating keep/drop thresholds.

**Risk assessment: LOW**

- The mpdecimate filter decides whether to drop visually-similar video frames.
  It is not security-critical — it doesn't parse untrusted input, handle memory
  allocation of attacker-controlled sizes, or process network data.
- The refactoring fixes a real behavioral bug: the old code would skip the
  similarity check during the "keep period" and would update the reference
  frame to a similar frame, causing reference drift.
- Frame ownership is handled correctly: `av_frame_clone()` before
  `ff_filter_frame()`, original freed appropriately in each case.
- No use-after-free, double-free, or buffer issues introduced.

**Additional note:** Dana Feng also added themselves to `.forgejo/CODEOWNERS`
as reviewer for `libavfilter/vf_mpdecimate.*` (`235d5fd3`). This is a
trust-escalation pattern worth monitoring but is common practice on
Forgejo/Gitea-hosted projects. Given the filter is non-security-critical,
this is low risk.

---

### 3. Ruikai Peng — `e90c2ff4` — "fix heap overflow in US ITU-T T.35 metadata parsing"

**File:** `libavcodec/libdav1d.c`
**Note:** Not a new contributor (8 prior commits), but worth examining as a
security-critical change.

**What it does:** Adds a bounds check before `bytestream2_get_be16u()` (the
**unchecked** variant) in the US country code path of ITU-T T.35 metadata
parsing. The UK country code path already had an equivalent check.

```c
case ITU_T_T35_COUNTRY_CODE_US:
+   if (bytestream2_get_bytes_left(&gb) < 2)
+       return AVERROR_INVALIDDATA;
    provider_code = bytestream2_get_be16u(&gb);
```

**Risk assessment: NONE (legitimate fix)**

- All 8 prior commits from this author are security fixes (recursion depth
  limits, OOB write fixes, bounds checks). This is clearly a security
  researcher, consistent with the "pwno.io" domain.
- The fix is minimal (2 lines), correct, and follows the exact pattern
  already used in the adjacent UK country code path.
- Includes a credible ASan trace in the commit message.
- Does not modify any other logic or code paths.

---

### 4. Test-Only Commits (Marcos Ashton, Sankalpa Sarkar)

**Marcos Ashton** added three FATE tests:
- `libavutil/tests/mathematics.c` — tests `av_gcd`, `av_rescale`, etc.
- `libavutil/tests/samplefmt.c` — tests sample format API functions
- `libavutil/tests/rc4.c` — tests RC4 encrypt/decrypt against RFC 6229 vectors

**Sankalpa Sarkar** added two FATE tests:
- `libavutil/tests/timecode.c` — tests timecode functions
- `tests/fate/hlsenc.mak` — tests HLS encoder features using lavfi-generated input

**Risk assessment: VERY LOW**

- All changes are confined to test files (`libavutil/tests/*.c`),
  test Makefiles (`tests/fate/*.mak`), and reference output files
  (`tests/ref/fate/*`).
- No production code is modified.
- RC4 test vectors are from RFC 6229 (publicly verifiable).
- HLS encoder tests use `testsrc2` lavfi input (no binary test fixtures
  that could contain crafted exploits).
- Makefile changes only add new test targets; no build flags or
  compilation options are altered.

---

## Summary

| Commit | Author | New? | Security-Critical? | Suspicious? |
|--------|--------|------|-------------------|-------------|
| `e33b3962` | Hankang Li | **Yes** | **Yes** (swscale) | No — standard pattern, Niedermayer sign-off |
| `63822ae2` | Dana Feng | **Yes** | No (filter logic) | No |
| `235d5fd3` | Dana Feng | **Yes** | No (CODEOWNERS) | Low — trust escalation, monitor |
| `e90c2ff4` | Ruikai Peng | No (8 prior) | **Yes** (decoder) | No — legitimate security researcher |
| `e18c8c53` | Marcos Ashton | **Yes** | No (tests only) | No |
| `66b1dbfb` | Marcos Ashton | **Yes** | No (tests only) | No |
| `117897bc` | Marcos Ashton | **Yes** | No (tests only) | No |
| `7b49a69f` | Sankalpa Sarkar | **Yes** | No (tests only) | No |
| `b4626746` | Sankalpa Sarkar | **Yes** | No (tests only) | No |

**Overall finding: No evidence of supply chain attack detected.** All commits
from new contributors are either pure test additions, non-security-critical
filter fixes, or legitimate integer overflow fixes using established project
patterns with maintainer sign-off. No commit exhibits the pattern of "fixing
a minor issue while introducing a worse one."

The commit most deserving of continued scrutiny is `e33b3962` (Hankang Li)
due to the combination of: new contributor + security-critical code path +
framing as a security fix. However, the code changes are purely mechanical
type casts that produce identical output, and the approach is validated by
the project's most senior maintainer making identical fixes in the same file.
