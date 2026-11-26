from core.iam_engine import analyse_iam_evidence
def run_iam_analysis(df,stale_days=90): return analyse_iam_evidence(df,stale_days=stale_days)
