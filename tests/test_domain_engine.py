import pandas as pd
from core.domain_engine import analyse_domain_evidence

def test_change_flags_unapproved_production_change():
    df=pd.DataFrame([{"change_id":"C1","environment":"Production","approval_status":"Pending","testing_status":"Passed","implementation_status":"Implemented","emergency_change":"No","post_implementation_review":"N/A"}])
    r=analyse_domain_evidence(df,"change")
    assert any(x["exception_code"]=="CHG-EX01" for x in r["exceptions"])

def test_cloud_flags_public_access():
    df=pd.DataFrame([{"asset_id":"S1","public_access":"Yes","encryption_enabled":"Yes","mfa_enabled":"Yes","logging_enabled":"Yes","security_group_open_to_world":"No","backup_enabled":"Yes"}])
    r=analyse_domain_evidence(df,"cloud")
    assert any(x["exception_code"]=="CLD-EX01" for x in r["exceptions"])

def test_backup_flags_rpo_breach():
    df=pd.DataFrame([{"asset_id":"DB1","last_backup_status":"Success","restore_test_status":"Passed","rpo_hours":2,"actual_rpo_hours":5}])
    r=analyse_domain_evidence(df,"backup")
    assert any(x["exception_code"]=="BCP-EX01" for x in r["exceptions"])
