# FFmpeg Supply Chain Security Review

**Date:** 2026-04-07
**Period analyzed:** Commits after 2026-02-15
**Total commits in period:** 71+ (non-merge, by commit date)
**Total unique new authors:** 28 individuals (32 email addresses)

## Methodology

Identified all authors whose first-ever commit to the repository falls on or
after 2026-02-15. Examined every commit from these new contributors for:
1. Changes to security-critical code (parsers, decoders, memory management,
   crypto, TLS, assembly)
2. "Security fixes" that might introduce worse vulnerabilities
3. Suspicious build system or test infrastructure changes
4. Trust-escalation patterns (e.g., adding oneself to CODEOWNERS)

All security-relevant commits were reviewed line-by-line with full diffs.

---

## Executive Summary

**28 new unique individuals contributed 71 commits. No supply chain attack
was definitively identified.** However, one commit warrants elevated scrutiny
(see Finding #1 below). The remaining commits are either demonstrably
legitimate security fixes, pure test additions, or benign feature work.

---

## High-Priority Findings

### Finding #1 (MEDIUM): Priyanshu Thapliyal — `d1bcaab2` — alsdec mantissa mask removal

**File:** `libavcodec/alsdec.c` (ALS lossless audio decoder)
**Change:** Removes `& 0x007fffffUL` mask from attacker-controlled 32-bit value

```c
// Before: constrained to 23-bit mantissa
ctx->raw_samples[c][i] = raw_mantissa[c][i] & 0x007fffffUL;

// After: full 32-bit value from bitstream written directly
ctx->raw_samples[c][i] = raw_mantissa[c][i];
```

**Context:** When integer residual is 0, Part A data provides the float
reconstruction. The `raw_mantissa` comes directly from the bitstream via
`get_bits_long(gb, 32)` (uncompressed) or MLZ decompression (compressed).

**Why it was flagged:**
- Removes an explicit input sanitization mask on attacker-controlled data
- Commit message ("preserve full float value in zero-truncated samples") is
  vague and doesn't reference any spec section, bug report, or test case
- The commit has no `Signed-off-by` from an established maintainer
- The 23-bit mask matched the IEEE 754 mantissa width, suggesting it was
  intentional

**Mitigating factors:**
- The value only flows to audio output samples (`int32_t` → output frame),
  not to any size calculations, array indices, or pointers
- The 32-bit read (`get_bits_long(gb, 32)`) in the uncompressed path
  suggests the encoder may write full 32-bit IEEE 754 floats, making the
  mask incorrect for proper reconstruction of sign/exponent
- No buffer overflow, use-after-free, or memory corruption is possible
  from this change
- The same author's other 4 commits are all clearly legitimate fixes

**Verdict: Not a memory safety vulnerability, but the mask removal weakens
input validation on untrusted data without clear justification. Recommend
verifying against the ISO 14496-3 ALS specification (Table 14.44) whether
Part A for zero-samples carries 23-bit mantissa or full 32-bit float.**

---

### Finding #2 (LOW): Dana Feng — CODEOWNERS self-addition

**Commit:** `235d5fd3`
**Change:** Added `@danaf` as reviewer for `libavfilter/vf_mpdecimate.*`

A new contributor adding themselves as a code reviewer is a trust-escalation
pattern. However, the mpdecimate filter is non-security-critical (video frame
decimation), and the contributor's code changes are well-structured and fix
real bugs. Low risk.

---

## Detailed Analysis by Contributor

### Nicholas Carlini (nicholas@carlini.com) — 3 commits — ALL LEGITIMATE

Nicholas Carlini is a well-known ML/security researcher (Google DeepMind).
All 3 commits fix real, verifiable security bugs:

1. **`3e8bec78`** — MPEGTS descriptor accounting: Fixes a **stack buffer
   overflow** where multiple IOD descriptors could overflow the
   `Mp4Descr mp4_descr[MAX_MP4_DESCR_COUNT]` array. The fix correctly
   passes remaining capacity and accumulates counts with `+=`.

2. **`55bf0e6c`** — JPEG-XS early return removal: Fixes a **use-after-free**
   where `return AVERROR_INVALIDDATA` left `pes->buffer` as a dangling
   pointer after `pkt->buf` shared the same `AVBufferRef`. The fix uses
   fall-through with `AV_PKT_FLAG_CORRUPT` flag instead.

3. **`39e19693`** — H.264 slice_num sentinel rejection: Fixes a **sentinel
   collision** where `slice_num` at 0xFFFF collides with the uninitialized
   marker in the `uint16_t` slice table, defeating deblocking boundary
   checks. Signed off by Michael Niedermayer.

### Priyanshu Thapliyal (priyanshuthapliyal2005@gmail.com) — 5 commits

Touches security-critical codec code (ALS decoder, PNG decoder).

1. **`d1bcaab2`** — **See Finding #1 above (MEDIUM scrutiny)**

2. **`febc8269`** — Error propagation: Correctly adds missing `ret =` and
   error check for `read_diff_float_data()` return value. **Legitimate fix.**

3. **`ae6f2339`** — Mantissa unpacking: Fixes TWO bugs in the compressed
   Part A path — missing pointer advancement and missing zero-sample guard.
   Buffer bounds are safe (`j` bounded by `nchars` which is validated
   against `larray` size). **Legitimate fix.**

4. **`e7b4ddc9`** — PNG EXIF overflow: **Important security fix.** The
   original check `exif_len & ~SIZE_MAX` is ALWAYS 0 (dead code). This
   meant `2 * exif_len` could silently wrap, bypassing the bounds check.
   The fix replaces it with `exif_len > SIZE_MAX / 2`, which correctly
   detects overflow. **Legitimate and important fix.**

5. **`1853c80e`** — INT_MIN UB: Replaces `abs()` with `FFABSU()` to avoid
   undefined behavior on `abs(INT_MIN)`. Standard FFmpeg pattern.
   **Legitimate fix.**

### Nariman-Sayed (narimansayed28@gmail.com) — 5 commits — ALL LEGITIMATE

Touches TLS/DTLS/WebRTC networking code.

1. **`477bf79b`** — SHA-1 → SHA-256 for self-signed certs. One-line change
   (`EVP_sha1()` → `EVP_sha256()`). No other TLS behavior modified.
   **Security improvement.**

2. **`b20f42b1`** — DTLS retransmission fix. Substantial rewrite of
   `dtls_handshake()` from blocking to non-blocking with `poll()` +
   `DTLSv1_handle_timeout()`. No cipher suites, cert verification, or
   security settings changed. Correctly restores blocking mode afterwards.
   **Legitimate fix.**

3. **`9bc4109b`** — Memory leak in `cert_from_pem_string()`. Simple fix:
   `BIO_free(mem)` was unreachable on error path. **Legitimate fix.**

4. **`186e3887`** — Uses `ffurl_closep` instead of `ffurl_close` to NULL
   the pointer after close, preventing potential use-after-free.
   **Legitimate fix.**

5. **`2501954d`** — RTCP RR packet loss clamping. **Legitimate fix.**

### Gil Portnoy (dddhkts1@gmail.com) — 5 commits

Codec parser fixes (H.266/VVC CBS, AAC USAC MPS212).

1. **`26dd9f9b`** — H.266 width/height typo fix in CBS syntax template
2. **`51606de0`** — H.266 rows/columns fix in CBS syntax template
3. **`e1d9080e`** — AAC USAC MPS212: wrong `end_band` parameter
4. **`d75b7c22`** — AAC USAC MPS212: typo in `huff_data_2d()`
5. **`8b9851b0`** — AAC USAC MPS212: off-by-one bounds check fix

These are small, focused fixes in codec bit-syntax parsing. The off-by-one
fix (#5) tightens a bounds check, not loosens it.

### David Christle (dev@christle.is) — 7 commits

NEON assembly for aarch64 color conversion + LoongArch fix.

All commits add new SIMD implementations with corresponding checkasm tests.
The assembly adds new code paths (not modifying existing ones). Each new
function has a matching test that validates correctness against the C
reference implementation.

The LoongArch fix (`8e591af3`) corrects residual handling for multi-row
slices — a correctness fix, not a security boundary change.

### Hankang Li (hankang201222@gmail.com) — 1 commit — LEGITIMATE

**`e33b3962`** — Integer overflow fix in libswscale color conversion.
Uses the standard `(int)((unsigned)a*b + ...)` pattern. Signed off by
Michael Niedermayer, who made 4 more identical fixes in the same file.
See initial analysis above.

### Dana Feng (danafeng@berkeley.edu / danaf@twosigma.com) — 3 commits — LEGITIMATE

mpdecimate filter logic fix + tests + CODEOWNERS addition. Non-security-
critical code. The refactoring correctly handles frame ownership (clone
before send, proper free in each case).

### Marcos Ashton (marcosashiglesias@gmail.com) — 13 commits

10 test additions + 3 small bug fixes:
- `5d70f084` — stereo3d: fix prefix matching in `*_from_name()` functions
- `9559a603` — vf_v360: fix operator precedence in stereo loop condition
- `a43ea8bf` — af_pan: fix sscanf() return value checks
- `dfa53aae` — bswap: fix implicit conversion warning in av_bswap64

All are small, focused correctness fixes. The bswap64 change fixes a
compiler warning without changing byte-swapping behavior. Test additions
are pure test code with no production code modifications.

### Sankalpa Sarkar (sankalpasarkar68@gmail.com) — 3 commits — LEGITIMATE

2 test additions + 1 non-test commit:
- `65eed073` — adds `avio_read()` return value checks in dss/dtshd/mlv
  demuxers. This ADDS error checking that was missing. **Security improvement.**

### Other New Contributors (1-2 commits each)

| Author | Commit(s) | Nature | Assessment |
|--------|-----------|--------|------------|
| Linke | `e44d76f6` av1 uvlc loop fix | Bounds fix in bitstream parser | Legitimate |
| Weidong Wang | `06d19d00` rsd extradata, `236dbc9f` xxan y_buffer | Input validation | Legitimate |
| Adrien Guinet | `da9a6d51` MOV multi-key decrypt | Feature (authored 2023) | Legitimate |
| Aditya Banavi | `31c2f814` GnuTLS DTLS fix | Handshake fix | Legitimate |
| Devraj Ajmera | `4a390fcd` RTP payload validation | Input validation | Legitimate |
| Huihui_Huang | `6e37545d` swscale lut leak fix | Memory leak fix | Legitimate |
| lompik | `38cd91c9` Vulkan planes fix | Correctness fix | Legitimate |
| Adrien Destugues | `5425be53` Haiku memalign | Platform fix (authored 2019) | Legitimate |
| Others | Various | Tests, features, minor fixes | Legitimate |

---

## Commits Most Deserving Continued Scrutiny

Ranked by risk level:

1. **`d1bcaab2`** (Priyanshu Thapliyal) — ALS mantissa mask removal.
   MEDIUM risk. Removes input sanitization mask without clear spec
   justification. Not exploitable for memory corruption but weakens
   defense-in-depth. Recommend spec verification.

2. **`235d5fd3`** (Dana Feng) — CODEOWNERS self-addition. LOW risk.
   Trust escalation pattern, but targets non-security-critical filter.

3. **`b20f42b1`** (Nariman-Sayed) — DTLS handshake rewrite. LOW risk.
   Substantial rewrite of network security code, but uses correct
   OpenSSL patterns and doesn't modify any security settings.

---

## Conclusion

After examining 71 commits from 28 new contributors, **no definitive
evidence of a supply chain attack was found.** The most suspicious commit
(`d1bcaab2`) removes an input sanitization mask in the ALS audio decoder,
but the change cannot cause memory corruption — only potentially incorrect
audio output values. All other security-relevant commits from new
contributors are demonstrably legitimate fixes that address real,
verifiable bugs.

Notable positive patterns observed:
- Most security-critical commits are signed off by Michael Niedermayer
  (29,850 prior commits) or other established maintainers
- Security fixes use established FFmpeg patterns (SUINT, FFABSU, etc.)
- New contributors providing NEON assembly also provide checkasm tests
- Test-only contributors don't touch production code
