# Preliminary Findings

Five experiments were conducted using real security patches.

Key observations:

1. API-based signatures can detect code reuse across packages.
2. Token-level signatures generate significant noise.
3. Validation fixes may be highly project-specific.
4. Regex and path-normalization fixes are difficult to generalize.
5. Generalized signatures reduce recall in text-based search.

## Experiment Comparison

| Experiment | Vulnerability Type | Signature Type | Matches Found | Noise Level | Generalizability | Lesson Learned |
|------------|-------------------|----------------|---------------|-------------|------------------|----------------|
| APT nullptr | NULL dereference | API + control flow | 4 | Medium | High | Combining API and control-flow signatures improves detection |
| libtiff overflow | Loop bounds | Macro token | 3 | High | Medium | Macro tokens alone introduce noise |
| libvips validation | Input validation | Project API | 0 | Low | Low | Project-specific APIs rarely generalize |
| rollup regex | Path normalization | Regex pattern | 0 | Low | Medium | Tool-specific logic does not generalize well |
| generalized search | Pattern abstraction | Generalized tokens | 0 | Low | High | Generalized signatures are better for ranking than search |

## Why a Hybrid Detection Pipeline is Necessary

The five experiments highlight complementary limitations of different
signature strategies.

Experiment 1 demonstrated that API-based signatures can detect code
reuse but often generate unrelated matches.

Experiment 2 showed that simple lexical tokens such as macros produce
high noise levels when used directly as search signatures.

Experiment 3 indicated that project-specific APIs rarely generalize
across unrelated packages.

Experiment 4 showed that tool-specific logic such as regex or path
normalization may not appear in other packages.

Experiment 5 demonstrated that aggressive signature generalization
reduces recall when used directly for search queries.

Together these results motivate a hybrid pipeline:

Patch
↓
Original signature search (high recall)
↓
Candidate matches
↓
Generalized pattern comparison
↓
Similarity scoring
↓
Ranked vulnerability clones

This approach preserves search recall while enabling structural
pattern detection and noise reduction.

Conclusion:

An effective clone detection pipeline should combine:

Patch -> Original signature search (high recall) -> Candidate matches -> Generalized pattern comparison -> Similarity scoring -> Ranked vulnerability clones

