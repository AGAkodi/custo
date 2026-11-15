# Evaluation methodology

`POST /api/evaluation/run` compares the frozen baseline and the currently approved rule on twelve deterministic held-out incidents: four seeds each for distributed attack, normal mistakes and benign distributed overlap. The held-out IP ranges and account IDs are disjoint from the distributed feedback fixture. Seeds are `DEMO_SEED + 100, 201, 302, 403`, and each case records its seed. The positive class is any non-benign incident; the unit is an incident, not an event. Held-out fixtures cannot generate proposals.

Each condition stores an assessment in HydraDB. The run record stores compact decision references, per-case outcomes and provenance, confusion counts, precision, recall, F1 and false-positive rate; the full decisions remain separate graph entities. Zero-denominator precision or recall is represented as zero.

For seed 42 and the feature-derived candidate from the default feedback fixture, the expected result is baseline TP 0, FP 0, TN 8, FN 4; adaptive TP 4, FP 4, TN 4, FN 0. This deliberately exposes a false-positive rate of 50% across eight benign cases. These cases are generated from three templates, not independent real-world samples. Twelve synthetic cases remain far too few to claim production accuracy; tuning against held-out cases would invalidate the comparison.
