# Preliminary Findings

A series of five exploratory experiments were conducted using real
security patches from upstream projects and the Debian Security
Tracker. The goal of these experiments was to evaluate whether
security patches can be transformed into effective search signatures
for detecting potential vulnerability clones across the Debian
archive.

The experiments applied the prototype **patch → signature → archive
search → verification** pipeline to different vulnerability types.

---

# Key Observations

Several important patterns emerged from these experiments.

1. **API-based signatures can detect cross-package code reuse**

   Functions and library APIs often remain stable across projects.
   Searching for these APIs can reveal related code fragments in other
   packages.

2. **Token-level signatures generate significant noise**

   Generic tokens such as macros or variable names frequently appear
   in unrelated codebases, producing many false positives.

3. **Validation fixes are often project-specific**

   Security fixes involving project-specific validation APIs rarely
   generalize across unrelated packages.

4. **Regex and path-normalization logic can be difficult to generalize**

   Vulnerabilities in build tools or language-specific utilities often
   rely on project-specific implementation details.

5. **Generalized signatures reduce recall in text-based search**

   Abstracting identifiers into generic tokens helps identify
   structural similarity, but generalized patterns cannot be used
   directly with lexical code search engines.

---

# Experiment Comparison

| Experiment                | Vulnerability Type  | Signature Type     | Matches Found  | Noise Level | Generalizability | Lesson Learned                                               |
| ------------------------- | ------------------- | ------------------ | -------------- | ----------- | ---------------- | ------------------------------------------------------------ |
| APT nullptr               | NULL dereference    | API + control flow | 4              | Medium      | High             | Combining API and control-flow signatures improves detection |
| libtiff overflow          | Loop bounds         | Macro token        | 3              | High        | Medium           | Macro tokens alone introduce noise                           |
| libvips validation        | Input validation    | Project API        | 1              | Medium      | Low              | Project-specific APIs rarely generalize                      |
| rollup path normalization | Path normalization  | Structural logic   | ~60 candidates | Medium      | Low              | Tool-specific logic rarely appears in unrelated packages     |
| generalized search        | Pattern abstraction | Generalized tokens | 0              | Low         | High             | Generalized signatures are better for ranking than search    |

---

# Why a Hybrid Detection Pipeline is Necessary

The experiments highlight complementary limitations of different
signature strategies.

Experiment 1 demonstrated that API-based signatures can detect code
reuse across packages, but they may also produce unrelated matches.

Experiment 2 showed that simple lexical tokens such as macros produce
high noise levels when used directly as search signatures.

Experiment 3 indicated that project-specific validation APIs rarely
generalize across unrelated packages.

Experiment 4 demonstrated that tool-specific logic such as path
normalization may not appear in other packages.

Experiment 5 showed that aggressive signature generalization reduces
recall when used directly for archive search.

Taken together, these results suggest that no single signature
strategy is sufficient.

---

# Hybrid Detection Pipeline

A practical vulnerability clone detection system should therefore
combine multiple techniques.

```
Patch
   ↓
Original signature extraction
   ↓
Archive search (high recall)
   ↓
Candidate retrieval
   ↓
Generalized pattern comparison
   ↓
Similarity scoring
   ↓
Ranked vulnerability clones
```

In this architecture:

* **Original signatures** maximize search recall by matching real
  code tokens present in source files.
* **Generalized signatures** enable structural comparison across
  slightly different implementations.
* **Similarity scoring and ranking** help prioritize the most
  promising candidate clones.

---

# Conclusion

These preliminary experiments demonstrate that security patches can
serve as an effective starting point for discovering potentially
related code fragments across large software archives.

However, different vulnerability types require different signature
strategies.

An effective vulnerability clone detection pipeline should therefore
combine multiple signals, including:

* API identifiers
* control-flow patterns
* structural code fragments
* generalized token representations

By integrating these signals within a unified pipeline, it becomes
possible to detect and rank potential vulnerability clones across the
Debian ecosystem at scale.

