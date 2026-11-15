# Custos judge walkthrough

Open https://custo-production.up.railway.app/ and sign in with the demo credentials supplied separately. In the workspace, use the reviewer token supplied separately for feedback, approval, and reset. Never publish credentials here.

1. Open **Lifecycle review**, enter the reviewer token, and select **Reset demo**. The hosted demo is shared: a reset affects all current visitors. Earlier graph records remain in an older namespace.
2. In **Incident lab**, choose **Distributed login attempts** and select **Run baseline**. The expected result is benign/monitor with no matching baseline rule: this is the intentional missed attack.
3. Select **Reveal outcome**. The fixture identifies credential stuffing. Enter the reviewer token and select **Create review proposal**.
4. On **Lifecycle review**, inspect the proposed thresholds, evidence, and benign regression preview. Approve it with a reason. This is an explicit reviewer action, not automatic activation.
5. Open **Memory graph** and inspect the incident, evidence, memory, proposal, and rule relationships. The graph comes from HydraDB; the diagram may show only a bounded selection, with a relationship list below it.
6. Return to **Incident lab**, choose **Unseen distributed variation**, and select **Run adaptive**. Inspect the classification, rule and memory influence in the decision trace. The held-out identities differ from the feedback scenario.
7. Open **Evaluation** and run the comparison. Explain both detected attacks and benign false positives. The default fixture previously produced four detections and four false positives among eight benign cases; report the actual run, not an assumed result. The twelve incidents are synthetic and do not establish real-world accuracy.
8. Refresh and revisit the graph and evaluation to check stored results. Reset again only when everyone is finished, because all visitors share the same demo session.

The candidate rule uses bounded feature-derived heuristics, with human review. It is not a general-purpose model trained on arbitrary incidents. The app is a demonstration and does not perform automated security response.
