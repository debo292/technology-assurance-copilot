# AI-Powered Technology Assurance & Regulatory Intelligence Copilot

A modular portfolio prototype demonstrating evidence-led technology assurance and a multi-framework regulatory intelligence layer.

## Run locally (Windows PowerShell)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

## Workspace
- **Overview:** executive-style landing dashboard and coverage view.
- **Regulatory Universe:** searchable framework catalogue across NIST, GDPR, India DPDP, PCI DSS, cloud, ISO, AI governance, RBI, SEBI, MAS, DORA and SOC 2.
- **Control Crosswalk:** illustrative cross-framework references for selected control objectives.
- **Evidence Intelligence:** retained deterministic IAM evidence checks.
- **Assessment Workpapers:** local SQLite assessment history.
- **Platform & Methodology:** architecture, data governance, limitations and roadmap.

## Important data-governance note
Framework catalogue entries are starter metadata. Crosswalks are illustrative portfolio mappings, not official equivalence statements or legal interpretations. Validate authoritative source text, current versions, entity applicability, effective dates, exceptions and regulator updates before using mappings in a real audit.

The project deliberately distinguishes laws/regulations, regulatory guidance, voluntary frameworks, international standards and industry assurance criteria. SOC 2 is an attestation framework, not a regulation. NIST RMF is a risk-management process; NIST SP 800-53 is a control catalogue. PCI DSS applies to relevant payment-card environments, not automatically to every system.

## Current capabilities
- Premium dark-themed Streamlit UI.
- Framework catalogue with jurisdiction/domain/instrument filters and official source links.
- Searchable control crosswalk with mapping caveats.
- CSV/XLSX evidence intake and deterministic checks across seven domains: IAM, change management, vulnerability/patch, backup/DR, security monitoring, third-party risk and cloud security.
- SQLite workpaper history and JSON/Markdown exports.

## Not implemented
Automated regulatory updates, full authoritative control text, complete framework mappings, legal applicability determination, cloud posture integrations, privacy/PCI/AI testing engines, OCR/PDF evidence ingestion, enterprise authentication/RBAC, tenant isolation, immutable logs, evidence hashing and formal AI evaluation.

## Safety
Use synthetic or explicitly authorised evidence only. Never upload employer/client confidential information or personal data. This prototype does not provide legal advice, an audit opinion, compliance certification or automated control-effectiveness conclusions.


## Domain-specific evidence templates
See `sample_evidence/`. The templates are synthetic examples designed to demonstrate starter rule logic. Each domain has limited checks and is not a full audit programme.
