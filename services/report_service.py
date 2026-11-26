def assessment_to_markdown(r):
    lines=[f"# {r.get('module','Technology Assurance')} — Workpaper","",f"- Status: {r.get('status')}",f"- Domain: {r.get('domain','IAM')}",f"- Population: {r.get('population')}",f"- Exceptions: {r.get('exception_count',0)}","","## Severity summary"]
    lines += [f"- {k.title()}: {v}" for k,v in r.get("summary",{}).items()]
    for x in r.get("exceptions",[]):
        lines += ["",f"## {x.get('exception_code')} — {x.get('finding')}",f"- Source row: {x.get('source_row')}",f"- Record ID: {x.get('record_id',x.get('user_id','Unknown'))}",f"- Severity: {x.get('severity')}",f"- Basis: {x.get('basis')}",f"- Auditor validation: {x.get('recommended_validation')}"]
    lines += ["","## Data quality considerations"]+[f"- {x}" for x in r.get("data_quality_issues",[])]
    lines += ["","## Limitations"]+[f"- {x}" for x in r.get("limitations",[])]
    lines += ["","## Auditor conclusion","Pending independent auditor validation."]
    return "\n".join(lines)
