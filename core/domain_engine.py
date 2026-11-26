"""Deterministic, explainable evidence checks for selected technology assurance domains."""
from datetime import datetime, timezone
import pandas as pd
import re

ALIASES = {
 "change": {
  "change_id":["change_id","ticket_id","change_number"], "environment":["environment","system_environment"],
  "approval_status":["approval_status","approved","change_approval"], "testing_status":["testing_status","test_status"],
  "implementation_status":["implementation_status","deployment_status","status"], "emergency_change":["emergency_change","is_emergency"],
  "post_implementation_review":["post_implementation_review","pir_status","post_change_review"]
 },
 "vulnerability": {
  "asset_id":["asset_id","host_id","hostname","system_id"], "severity":["severity","risk_rating","finding_severity"],
  "status":["status","remediation_status","finding_status"], "days_open":["days_open","age_days"],
  "remediation_sla_days":["remediation_sla_days","sla_days"], "patch_status":["patch_status","patch_compliance"]
 },
 "backup": {
  "asset_id":["asset_id","system_id","hostname"], "last_backup_status":["last_backup_status","backup_status"],
  "restore_test_status":["restore_test_status","restore_status"], "rpo_hours":["rpo_hours","approved_rpo_hours"],
  "actual_rpo_hours":["actual_rpo_hours","observed_rpo_hours"], "last_backup_date":["last_backup_date","backup_date"]
 },
 "monitoring": {
  "asset_id":["asset_id","system_id","hostname"], "log_enabled":["log_enabled","logging_enabled"],
  "last_log_date":["last_log_date","last_event_date"], "alert_severity":["alert_severity","severity"],
  "alert_status":["alert_status","status"], "incident_ticket":["incident_ticket","ticket_id"]
 },
 "third_party": {
  "vendor_id":["vendor_id","supplier_id"], "criticality":["criticality","vendor_criticality"],
  "due_diligence_status":["due_diligence_status","due_diligence","assessment_status"],
  "soc_report_status":["soc_report_status","soc_status"], "soc_report_expiry":["soc_report_expiry","report_expiry"],
  "contract_security_clauses":["contract_security_clauses","security_clauses"],
  "last_review_date":["last_review_date","review_date"]
 },
 "cloud": {
  "asset_id":["asset_id","resource_id","resource_name"], "public_access":["public_access","publicly_accessible"],
  "encryption_enabled":["encryption_enabled","encryption_at_rest"], "mfa_enabled":["mfa_enabled","mfa"],
  "logging_enabled":["logging_enabled","logs_enabled"], "security_group_open_to_world":["security_group_open_to_world","open_to_world","0_0_0_0_0"],
  "backup_enabled":["backup_enabled","backup_configured"]
 }
}

def _norm(v):
    return re.sub(r"[^a-z0-9]+","_",str(v).strip().lower()).strip("_")

def _truth(v):
    return str(v).strip().lower() in {"yes","true","1","y","enabled","active","complete","completed","approved","passed","success","compliant"}

def _false(v):
    return str(v).strip().lower() in {"no","false","0","n","disabled","inactive","failed","not done","not completed","missing","overdue","open"}

def _standardise(df, domain):
    data=df.copy()
    original={_norm(c):c for c in data.columns}
    mappings=[]
    for target, aliases in ALIASES[domain].items():
        src=next((original[a] for a in aliases if a in original),None)
        if src and target not in data.columns:
            data[target]=data[src]; mappings.append(f"{src} → {target}")
    data.columns=[_norm(c) for c in data.columns]
    return data,mappings

def analyse_domain_evidence(df, domain, thresholds=None):
    thresholds=thresholds or {}
    labels={
      "change":"Change Management","vulnerability":"Vulnerability & Patch Management",
      "backup":"Backup & Disaster Recovery","monitoring":"Security Monitoring & Logging",
      "third_party":"Third-Party Risk Management","cloud":"Cloud Security Configuration"
    }
    if df is None or df.empty:
        return {"module":labels.get(domain,domain),"status":"Insufficient data","population":0,"summary":{"critical":0,"high":0,"medium":0,"low":0},"exception_count":0,"exceptions":[],"data_quality_issues":["No records supplied."],"limitations":["An empty population cannot support an audit conclusion."]}
    d,mappings=_standardise(df,domain); issues=[]; findings=[]
    id_col="asset_id" if domain in {"vulnerability","backup","monitoring","cloud"} else ("vendor_id" if domain=="third_party" else "change_id")
    if id_col not in d.columns:
        issues.append(f"Missing recommended identifier field: {id_col}.")
    elif d[id_col].astype(str).duplicated(keep=False).any():
        issues.append("Duplicate identifiers detected; confirm population uniqueness.")
    def add(mask,code,title,severity,basis,action):
        if not isinstance(mask,pd.Series): return
        for idx in d.index[mask.fillna(False)]:
            row=d.loc[idx]
            findings.append({"source_row":int(d.index.get_loc(idx))+2,"record_id":str(row.get(id_col,"Unknown")),"exception_code":code,"finding":title,"severity":severity,"basis":basis,"recommended_validation":action})
    def has(*cols): return all(c in d.columns for c in cols)
    def yes(col): return d[col].map(_truth)
    def no(col): return d[col].map(_false)
    if domain=="change":
        prod=d.environment.astype(str).str.lower().str.contains("prod") if "environment" in d else pd.Series(False,index=d.index)
        implemented=d.implementation_status.astype(str).str.lower().isin(["implemented","completed","deployed","closed"]) if "implementation_status" in d else pd.Series(True,index=d.index)
        if has("approval_status"): add(prod&implemented&~yes("approval_status"),"CHG-EX01","Production change without recorded approval","High","Production change is implemented but approval is not recorded as approved.","Inspect change ticket, approval timestamp and emergency-change authorisation.")
        if has("testing_status"): add(prod&implemented&~yes("testing_status"),"CHG-EX02","Production change testing not evidenced","High","Production change is implemented but testing status is not passed/completed.","Obtain test evidence, UAT/security testing where applicable and deployment validation.")
        if has("emergency_change","post_implementation_review"):
            add(yes("emergency_change")&~yes("post_implementation_review"),"CHG-EX03","Emergency change post-implementation review missing","Medium","Emergency change does not show a completed post-implementation review.","Verify emergency classification, retrospective approval and PIR completion.")
    elif domain=="vulnerability":
        if has("severity","status","days_open","remediation_sla_days"):
            days=pd.to_numeric(d.days_open,errors="coerce"); sla=pd.to_numeric(d.remediation_sla_days,errors="coerce")
            open_=~d.status.astype(str).str.lower().isin(["closed","remediated","resolved","false positive"])
            overdue=open_&days.notna()&sla.notna()&(days>sla)
            crit=d.severity.astype(str).str.lower().isin(["critical","high","sev1","sev2"])
            add(overdue&crit,"VUL-EX01","Critical/high vulnerability overdue against remediation SLA","Critical","Open critical/high finding age exceeds its recorded remediation SLA.","Validate scanner finding, asset exposure, compensating controls, approved exception and remediation evidence.")
            add(overdue&~crit,"VUL-EX02","Vulnerability overdue against remediation SLA","High","Open vulnerability age exceeds its recorded remediation SLA.","Validate risk rating, SLA, remediation plan and risk acceptance.")
        if has("patch_status"):
            add(no("patch_status"),"PAT-EX01","Patch compliance not evidenced","High","Patch status is recorded as failed, disabled or non-compliant.","Inspect patch deployment records, exception approval and compensating controls.")
    elif domain=="backup":
        if has("last_backup_status"): add(no("last_backup_status"),"BKP-EX01","Backup job failure or status not successful","High","Latest backup status is not recorded as successful.","Inspect backup console logs, failed-job tickets, retry evidence and data protection scope.")
        if has("restore_test_status"): add(no("restore_test_status"),"BKP-EX02","Restore testing not evidenced","High","Restore test is not recorded as successful/completed.","Obtain restore test results, sample scope, integrity checks and business sign-off.")
        if has("rpo_hours","actual_rpo_hours"):
            rpo=pd.to_numeric(d.rpo_hours,errors="coerce"); actual=pd.to_numeric(d.actual_rpo_hours,errors="coerce")
            add(rpo.notna()&actual.notna()&(actual>rpo),"BCP-EX01","Observed recovery point exceeds approved RPO","Critical","Observed recovery point objective exceeds the approved RPO value.","Validate service-level RPO, test scenario, data loss calculation and approved exception.")
    elif domain=="monitoring":
        if has("log_enabled"): add(no("log_enabled"),"MON-EX01","Logging not enabled or not evidenced","High","Logging status is not recorded as enabled.","Validate log source onboarding, required event types, retention and monitoring coverage.")
        if has("alert_severity","alert_status"):
            critical=d.alert_severity.astype(str).str.lower().isin(["critical","high","sev1","sev2"])
            unresolved=~d.alert_status.astype(str).str.lower().isin(["closed","resolved","false positive","completed"])
            add(critical&unresolved,"MON-EX02","High-severity security alert remains unresolved","High","High/critical alert is not recorded as closed or resolved.","Inspect SIEM alert, triage notes, incident linkage, escalation and closure approval.")
    elif domain=="third_party":
        if has("criticality","due_diligence_status"):
            critical=d.criticality.astype(str).str.lower().isin(["critical","high","tier 1","tier1"])
            add(critical&~yes("due_diligence_status"),"TPR-EX01","Critical vendor due diligence not evidenced","High","Critical/high vendor does not show completed due diligence.","Obtain risk assessment, security due diligence, approval and residual risk acceptance.")
        if has("soc_report_status"): add(no("soc_report_status"),"TPR-EX02","Vendor assurance report missing or not current","Medium","SOC/independent assurance status is not recorded as current/available.","Obtain current assurance report, review scope, exceptions, bridge letter and complementary user entity controls.")
        if has("contract_security_clauses"): add(no("contract_security_clauses"),"TPR-EX03","Contractual security clauses not evidenced","High","Contract security clauses are not recorded as present.","Review security schedule, breach notification, audit rights, subcontracting and exit clauses.")
    elif domain=="cloud":
        for col,code,title,sev,action in [
          ("public_access","CLD-EX01","Cloud resource publicly accessible","Critical","Validate intended exposure, authentication, network restriction and business approval."),
          ("encryption_enabled","CLD-EX02","Cloud encryption not enabled or evidenced","High","Validate data classification, encryption at rest/in transit and key management."),
          ("mfa_enabled","CLD-EX03","MFA not enabled or evidenced","High","Validate identity provider policy, privileged identities and approved exceptions."),
          ("logging_enabled","CLD-EX04","Cloud logging not enabled or evidenced","High","Validate audit logging, central collection, retention and alerting."),
          ("security_group_open_to_world","CLD-EX05","Cloud security group open to the internet","Critical","Validate exposed ports, source ranges, service necessity and remediation."),
          ("backup_enabled","CLD-EX06","Cloud backup not enabled or evidenced","Medium","Validate workload recovery requirements, backup policy and restore tests.")]:
            if col in d: add(yes(col),code,title,sev,f"Evidence field {col} indicates a potentially insecure configuration.",action) if col in {"public_access","security_group_open_to_world"} else add(no(col),code,title,sev,f"Evidence field {col} indicates a missing or disabled safeguard.",action)
    order={"Critical":0,"High":1,"Medium":2,"Low":3}; findings.sort(key=lambda x:(order[x["severity"]],x["source_row"]))
    summary={s.lower():sum(x["severity"]==s for x in findings) for s in ["Critical","High","Medium","Low"]}
    limitations=["Rule matches are indicators for auditor investigation, not confirmed control failures.","Source authenticity, completeness, accuracy and population integrity require independent validation.","The checks are starter procedures and do not cover every requirement in any framework.","Thresholds and expected states must be aligned to approved policies, risk appetite and regulatory scope."]
    return {"module":labels[domain],"domain":domain,"status":"Analysis completed","population":int(len(d)),"column_mappings":mappings,"data_quality_issues":issues,"summary":summary,"exception_count":len(findings),"exceptions":findings,"limitations":limitations}
