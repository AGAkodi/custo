from app.evaluation import metrics


def test_metrics_count_false_positives_and_misses():
    rows = [
        {"label": "distributed_credential_stuffing", "result": {"classification": "benign"}},
        {"label": "benign", "result": {"classification": "distributed_credential_stuffing"}},
        {"label": "benign", "result": {"classification": "benign"}},
    ]
    result = metrics(rows, "result")
    assert (result["tp"], result["fp"], result["tn"], result["fn"]) == (0, 1, 1, 1)
    assert result["false_positive_rate"] == 0.5
