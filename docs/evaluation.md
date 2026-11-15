# Evaluation methodology

`POST /api/evaluation/run` compares the frozen baseline and the currently approved rule on twelve deterministic held-out incidents: four seeds each for distributed attack, normal mistakes and benign distributed overlap. The held-out IP ranges and account IDs are disjoint from the distributed feedback fixture. Seeds are `DEMO_SEED + 100, 201, 302, 403`, and each case records its seed. The positive class is any non-benign incident; the unit is an incident, not an event. Held-out fixtures cannot generate proposals.

Each condition stores an assessment in HydraDB. The run record stores compact decision references, per-case outcomes and provenance, confusion counts, precision, recall, F1 and false-positive rate; the full decisions remain separate graph entities. Zero-denominator precision or recall is represented as zero.

For seed 42 and the feature-derived candidate from the default feedback fixture, the expected result is baseline TP 0, FP 0, TN 8, FN 4; adaptive TP 4, FP 4, TN 4, FN 0. This deliberately exposes a false-positive rate of 50% across eight benign cases. These cases are generated from three templates, not independent real-world samples. Twelve synthetic cases remain far too few to claim production accuracy; tuning against held-out cases would invalidate the comparison.

## Hosted demonstration result

In the Railway demo, a reviewer approved the feature-derived distributed-login proposal. The held-out variation was flagged as distributed credential stuffing and the decision trace named the approved rule version, supporting memory, and evidence. Running the twelve-case evaluation produced baseline TP 0, FP 0, TN 8, FN 4 and adaptive TP 4, FP 4, TN 4, FN 0. The adaptive false-positive rate was therefore 50% in this synthetic sample. The graph showed the evidence, memory, proposal, rule version, and downstream influence relationships. After restarting HydraDB, those graph records remained visible and another held-out assessment cited the same rule and memory. This is a single restart check, not a durability or real-world accuracy guarantee.

