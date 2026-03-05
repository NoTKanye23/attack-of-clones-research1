# Preliminary Experiments for Debian Clone Detection

## Objective
Evaluate feasibility of deriving code search signatures from security patches.

---

## Experiment 1 – NULL Pointer Dereference

CVE: <APT example>

Patch fragment:
...

Candidate signatures:
...

Observation:
...

---

## Experiment 2 – Stack Overflow (libtiff)

CVE: CVE-2025-61144

Patch fragment:
for (s = 0; (s < spp) && (s < MAX_SAMPLES); s++)

Observation:
Macro-based signatures produce high noise.

---

## Experiment 3 – Input Validation (libvips)

CVE: CVE-2026-3147

Patch fragment:
if (!g_str_is_ascii(csv->whitespace) || ...

Observation:
API-based validation checks produce stronger signatures.
