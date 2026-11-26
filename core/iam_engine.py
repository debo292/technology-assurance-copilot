"""Explainable IAM rules. Results are indicators requiring auditor validation."""
from datetime import datetime, timezone
import re
import pandas as pd
ALIASES={"user_id":["user_id","userid","employee_id","account_id","id"],"username":["username","user_name","login","account_name"],"employment_status":["employment_status","employee_status","worker_status"],"account_status":["account_status","status","account_state"],"privileged":["privileged","is_privileged","admin","is_admin"],"manager_approval":["manager_approval","approval_status","approved_by_manager"],"access_review_status":["access_review_status","review_status","recertification_status"],"last_login":["last_login","last_logon","last_sign_in"]}
def norm(x): return re.sub(r"[^a-z0-9]+","_",str(x).strip().lower()).strip("_")
def standardise(df):
    out=df.copy(); cols={norm(c):c for c in out.columns}; mappings=[]
    for target,aliases in ALIASES.items():
        src=next((cols[a] for a in aliases if a in cols),None)
        if src and src!=target: out[target]=out[src]; mappings.append(f"{src} -> {target}")
    out.columns=[norm(c) for c in out.columns]
    return out,mappings
def isin(s,values): return s.fillna("").astype(str).str.strip().str.lower().isin(values)
def analyse_iam_evidence(df,stale_days=90,as_of=None):
    if df is None or df.empty:
        return {"module":"IAM Evidence Intelligence","status":"Insufficient data","population":0,"summary":{"critical":0,"high":0,"medium":0,"low":0},"exception_count":0,"exceptions":[],"data_quality_issues":["No records supplied."],"limitations":["An empty population cannot support an audit conclusion."]}
    data,mappings=standardise(df); quality=[]; missing=[x for x in ["user_id","employment_status","account_status"] if x not in data]
    if missing: quality.append("Missing key fields: "+", ".join(missing))
    if "user_id" in data:
        dup=int(data["user_id"].astype(str).duplicated(keep=False).sum())
        if dup: quality.append(f"{dup} rows have duplicated user identifiers.")
        blank=int(data["user_id"].isna().sum()+data["user_id"].astype(str).str.strip().eq("").sum())
        if blank: quality.append(f"{blank} rows have blank user identifiers.")
    exceptions=[]
    def add(mask,code,title,severity,basis,action):
        for idx in data.index[mask.fillna(False)]:
            row=data.loc[idx]; exceptions.append({"source_row":int(idx)+2,"user_id":str(row.get("user_id","Unknown")),"username":str(row.get("username","Unknown")),"exception_code":code,"finding":title,"severity":severity,"basis":basis,"recommended_validation":action})
    if {"employment_status","account_status"}.issubset(data.columns):
        departed=isin(data.employment_status,{"terminated","inactive","resigned","separated"}); active=isin(data.account_status,{"active","enabled","open"})
        add(departed&active,"IAM-EX01","Departed user with active account","Critical","Employment status indicates departure while account status is active.","Reconcile HR termination date with IAM disablement timestamp and investigate any approved exception.")
    if "privileged" in data:
        priv=isin(data.privileged,{"yes","true","1","y","admin","privileged"})
        if "manager_approval" in data:
            approved=isin(data.manager_approval,{"yes","approved","true","1","y"})
            add(priv&~approved,"IAM-EX02","Privileged access without recorded approval","High","Record is marked privileged but approval is not recorded as approved.","Inspect access request, approval trail, role assignment and emergency access process.")
        if "access_review_status" in data:
            reviewed=isin(data.access_review_status,{"complete","completed","reviewed","approved"})
            add(priv&~reviewed,"IAM-EX03","Privileged account review not evidenced","High","Privileged account does not show a completed access review.","Obtain review evidence, reviewer identity, date and remediation details.")
    if "access_review_status" in data:
        reviewed=isin(data.access_review_status,{"complete","completed","reviewed","approved"})
        add(~reviewed,"IAM-EX04","Access review not evidenced as complete","Medium","Record does not show a completed review status.","Confirm scope, reviewer sign-off, completion date and follow-up evidence.")
    if "last_login" in data:
        as_of=as_of or datetime.now(timezone.utc); dates=pd.to_datetime(data.last_login,errors="coerce",utc=True); age=(pd.Timestamp(as_of)-dates).dt.days
        add(dates.notna()&(age>stale_days),"IAM-EX05",f"No login observed for more than {stale_days} days","Medium",f"Last-login date exceeds configured {stale_days}-day threshold.","Confirm account necessity, service-account exception and dormant-access policy.")
    order={"Critical":0,"High":1,"Medium":2,"Low":3}; exceptions.sort(key=lambda x:(order[x["severity"]],x["source_row"]))
    summary={s.lower():sum(e["severity"]==s for e in exceptions) for s in ["Critical","High","Medium","Low"]}
    return {"module":"IAM Evidence Intelligence","status":"Analysis completed" if not missing else "Completed with data limitations","population":int(len(data)),"column_mappings":mappings,"data_quality_issues":quality,"summary":summary,"exception_count":len(exceptions),"exceptions":exceptions,"limitations":["Rule matches are indicators for investigation, not confirmed control failures.","Source authenticity, completeness, accuracy and population integrity require independent validation.","Dormant-account threshold is configurable and must align with approved policy.","Multiple rules may flag the same account for different reasons."]}
