import pandas as pd
from core.iam_engine import analyse_iam_evidence
def test_departed_active_account_flagged():
    df=pd.DataFrame([{"user_id":"U1","employment_status":"Terminated","account_status":"Active","privileged":"No","manager_approval":"Approved","access_review_status":"Completed"}])
    assert any(x["exception_code"]=="IAM-EX01" for x in analyse_iam_evidence(df)["exceptions"])
def test_empty_population():
    assert analyse_iam_evidence(pd.DataFrame())["status"]=="Insufficient data"
def test_sample_population():
    df=pd.read_csv("sample_evidence/iam_access_population.csv")
    assert analyse_iam_evidence(df)["population"]==8
