# Local demo

1. Start HydraDB, backend and frontend using the README. Configure `REVIEWER_TOKEN` in `.env` and restart the backend. Open Lifecycle review, enter the reviewer token and select Reset demo to begin in a fresh namespace. Previous graph data remains stored.
2. In Incident lab choose Distributed login attempts, run baseline and inspect the benign/no-match assessment.
3. Reveal the confirmed label, enter the reviewer token and create a proposal. In Lifecycle review inspect the evidence and benign regression controls; approve with a reason.
4. In Memory graph inspect evidence, proposal, rule and influenced assessments. The diagram is bounded and the full relationship list is available below it.
5. In Incident lab choose Unseen distributed variation and run adaptive; inspect its rule and memory influence.
6. Run Evaluation. Explain both the detected attack and the false positive on benign overlapping behavior. The numbers are synthetic and sample size is twelve.
7. Use rollback in Lifecycle review if you need to return to the baseline; historical records remain.

A silent browser recording is available at `docs/media/custos-demo.webm`. Public deployment and a narrated submission video remain deferred.
