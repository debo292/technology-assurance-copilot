import streamlit as st
import pandas as pd
import json
from pathlib import Path
from core.config import *
from core.controls import load_controls
from services.evidence_service import load_uploaded_evidence
from services.iam_service import run_iam_analysis
from services.storage import save_assessment, list_assessments
from services.report_service import assessment_to_markdown

st.set_page_config(page_title="Technology Assurance | Regulatory Intelligence", page_icon="◈", layout="wide", initial_sidebar_state="expanded")

# Premium dark navy / teal visual system
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --ink:#e8eef7; --muted:#91a0b5; --panel:#111c2d; --panel2:#17243a; --line:#26364d; --teal:#42d6c2; --blue:#79aaff; }
html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
.stApp { background: radial-gradient(circle at 80% 0%, #1a3150 0%, #0b1422 38%, #0a1220 100%); color:var(--ink); }
.block-container { padding-top:1.5rem; max-width:1450px; }
[data-testid="stSidebar"] { background:linear-gradient(180deg,#101c2e,#0b1422); border-right:1px solid #26364d; }
[data-testid="stSidebar"] * { color:#dce7f5; }
h1,h2,h3 { font-family:'Manrope',sans-serif; letter-spacing:-.035em; }
h1 { font-size:2.05rem!important; font-weight:800!important; }
h2 { font-size:1.35rem!important; font-weight:750!important; }
h3 { font-size:1.05rem!important; font-weight:700!important; }
p, label, .stMarkdown { color:#dce6f3; }
small, .muted { color:var(--muted); }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#17263b,#111c2d); border:1px solid #2a3b54; padding:15px 17px; border-radius:15px; }
div[data-testid="stMetricLabel"] { color:#9eafc4; }
div[data-testid="stMetricValue"] { color:#f3f7fc; font-family:'Manrope'; }
div[data-testid="stMetricDelta"] { color:#42d6c2; }
.stButton>button, .stDownloadButton>button { border-radius:10px; border:1px solid #36516e; background:linear-gradient(135deg,#1d4560,#176a70); color:white; font-weight:650; min-height:2.55rem; }
.stButton>button:hover, .stDownloadButton>button:hover { border-color:#42d6c2; color:white; }
div[data-testid="stDataFrame"] { border:1px solid #2a3b54; border-radius:12px; overflow:hidden; }
div[data-testid="stExpander"] { background:#111c2d; border:1px solid #26364d; border-radius:12px; }
.stTabs [data-baseweb="tab-list"] { gap:8px; }
.stTabs [data-baseweb="tab"] { background:#152238; border-radius:9px 9px 0 0; padding:10px 16px; }
.stTabs [aria-selected="true"] { background:#1c3c50!important; color:#53e0ce!important; }
.hero { padding:26px 28px; border:1px solid #29425d; border-radius:20px; background:linear-gradient(120deg,rgba(26,54,80,.96),rgba(17,30,48,.94)); box-shadow:0 16px 45px rgba(0,0,0,.18); }
.eyebrow { color:#55decf; text-transform:uppercase; letter-spacing:.16em; font-size:.69rem; font-weight:800; }
.hero-title { font-family:'Manrope'; font-size:2rem; font-weight:800; color:#f2f7fc; line-height:1.14; margin:.45rem 0 .6rem; }
.hero-copy { color:#b5c5d8; font-size:.97rem; max-width:850px; }
.pill { display:inline-block; border:1px solid #35536d; background:#14283d; color:#a9d7e2; padding:5px 10px; border-radius:30px; font-size:.72rem; margin:3px 5px 3px 0; }
.section-kicker { color:#58d9ca; font-size:.72rem; letter-spacing:.13em; text-transform:uppercase; font-weight:800; margin-bottom:6px; }
.card { background:linear-gradient(145deg,#142238,#101b2c); border:1px solid #293b54; border-radius:15px; padding:17px 18px; min-height:118px; }
.card-title { color:#eff5fb; font-weight:750; font-size:1rem; margin-bottom:6px; }
.card-copy { color:#9eafc4; font-size:.83rem; line-height:1.45; }
.card-tag { color:#55dccc; font-size:.68rem; text-transform:uppercase; letter-spacing:.1em; font-weight:800; }
hr { border-color:#26364d!important; }
</style>
""", unsafe_allow_html=True)

BASE = Path(__file__).resolve().parent
framework_path = BASE/"data"/"framework_catalogue.csv"
crosswalk_path = BASE/"data"/"control_crosswalk.csv"
frameworks = pd.read_csv(framework_path)
crosswalk = pd.read_csv(crosswalk_path)
controls = load_controls(CONTROL_LIBRARY_PATH)
DOMAIN_META = {'IAM & Privileged Access': ('iam', 'iam_access_population.csv', 'IAM access population with employee status, account status, privilege and review fields.'), 'Change Management': ('change', 'change_management.csv', 'Production change tickets with approvals, testing, implementation and emergency review.'), 'Vulnerability & Patch Management': ('vulnerability', 'vulnerability_patch.csv', 'Vulnerability findings with severity, age, remediation SLA and patch status.'), 'Backup & Disaster Recovery': ('backup', 'backup_dr.csv', 'Backup job status, restore-test evidence and RPO measurements.'), 'Security Monitoring & Logging': ('monitoring', 'security_monitoring.csv', 'Log source status and security alert triage records.'), 'Third-Party Risk Management': ('third_party', 'third_party_risk.csv', 'Vendor criticality, due diligence, assurance report and contract security indicators.'), 'Cloud Security Configuration': ('cloud', 'cloud_security.csv', 'Cloud resource exposure, encryption, MFA, logging, security group and backup settings.')}

def card(title, copy, tag=""):
    st.markdown(f'<div class="card"><div class="card-tag">{tag}</div><div class="card-title">{title}</div><div class="card-copy">{copy}</div></div>', unsafe_allow_html=True)

def header(kicker, title, subtitle):
    st.markdown(f'<div class="section-kicker">{kicker}</div><h1 style="margin-top:0">{title}</h1><p style="color:#9eafc4;margin-top:-8px">{subtitle}</p>', unsafe_allow_html=True)

with st.sidebar:
    st.markdown('<div style="padding:12px 4px 18px"><div style="font-size:1.55rem;color:#53dfcf;font-weight:900">◈ TA</div><div style="font-family:Manrope;font-size:1rem;font-weight:800;color:#f0f5fa">TECHNOLOGY<br>ASSURANCE</div><div style="font-size:.67rem;color:#8498b0;letter-spacing:.13em;margin-top:7px">REGULATORY INTELLIGENCE</div></div>', unsafe_allow_html=True)
    st.markdown("---")
    page = st.radio("WORKSPACE", ["Overview","Regulatory Universe","Control Crosswalk","Evidence Intelligence","Assessment Workpapers","Platform & Methodology"], label_visibility="visible")
    st.markdown("---")
    st.markdown('<div style="font-size:.72rem;color:#8ea2b9">PORTFOLIO BUILD · V2.1<br>Evidence-led · Human-reviewed</div>', unsafe_allow_html=True)

if page == "Overview":
    st.markdown("""
    <div class="hero">
      <div class="eyebrow">Technology risk · Cyber assurance · Regulatory intelligence</div>
      <div class="hero-title">One assurance workspace.<br>Multiple frameworks. Clearer risk decisions.</div>
      <div class="hero-copy">A modular portfolio prototype for assessing technology evidence, exploring regulatory obligations and mapping common control objectives across cybersecurity, privacy, cloud, payments and AI governance frameworks.</div>
      <div style="margin-top:15px"><span class="pill">NIST RMF & 800-53</span><span class="pill">GDPR & DPDP</span><span class="pill">PCI DSS</span><span class="pill">RBI · SEBI · MAS</span><span class="pill">DORA</span><span class="pill">EU AI Act · NIST AI RMF</span></div>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    a,b,c,d = st.columns(4)
    a.metric("Frameworks catalogued", len(frameworks))
    b.metric("Mapped control objectives", crosswalk.control_id.nunique())
    c.metric("Crosswalk references", len(crosswalk))
    d.metric("Operational audit domains", "07")
    st.markdown("### Assurance workspace")
    cols = st.columns(3)
    with cols[0]: card("Regulatory Universe","Browse frameworks by jurisdiction, domain, instrument type, version and applicability notes.","01 · EXPLORE")
    with cols[1]: card("Control Crosswalk","Explore indicative mappings between control objectives and multiple regulatory or standards references.","02 · MAP")
    with cols[2]: card("Evidence Intelligence","Run deterministic IAM evidence checks, review exceptions and save workpapers.","03 · ASSESS")
    st.markdown("### Coverage map")
    domains = frameworks.groupby("domain").size().sort_values(ascending=False)
    st.bar_chart(domains, color="#42d6c2", horizontal=True)
    st.markdown("### Design principles")
    p1,p2,p3 = st.columns(3)
    with p1: card("Evidence before conclusions","A rule match is an investigation indicator. It is not automatically a confirmed control failure.","AUDITABILITY")
    with p2: card("Applicability before compliance","Regulatory obligations depend on entity type, jurisdiction, service, system and scope.","SCOPE")
    with p3: card("Human accountability","Auditors, risk owners and legal/compliance teams validate mappings and final conclusions.","GOVERNANCE")
    st.caption("Prototype dataset: curated illustrative mappings for demonstration. Not a complete legal register, regulatory interpretation or compliance certification.")

elif page == "Regulatory Universe":
    header("01 / FRAMEWORK LIBRARY","Regulatory Universe","A structured catalogue of regulations, standards, guidance and industry assurance criteria.")
    c1,c2,c3 = st.columns(3)
    with c1: domain = st.selectbox("Domain", ["All"]+sorted(frameworks.domain.unique().tolist()))
    with c2: jurisdiction = st.selectbox("Jurisdiction", ["All"]+sorted(frameworks.jurisdiction.unique().tolist()))
    with c3: instrument = st.selectbox("Instrument type", ["All"]+sorted(frameworks.instrument_type.unique().tolist()))
    view = frameworks.copy()
    if domain!="All": view=view[view.domain==domain]
    if jurisdiction!="All": view=view[view.jurisdiction==jurisdiction]
    if instrument!="All": view=view[view.instrument_type==instrument]
    st.caption(f"{len(view)} frameworks shown · {len(frameworks)} in catalogue")
    for _,r in view.iterrows():
        with st.container(border=True):
            left,right = st.columns([4,1])
            with left:
                st.markdown(f"**{r['framework']}**  ·  `{r['version']}`")
                st.caption(f"{r['category']}  |  {r['jurisdiction']}  |  {r['instrument_type']}")
                st.write(r["coverage"])
                st.caption("Applicability: "+r["applicability_note"])
            with right:
                st.link_button("Official source ↗",r["official_source"],use_container_width=True)
    st.info("Framework inclusion does not establish that a requirement applies to a particular organisation. Validate entity scope, territorial reach, effective dates, exemptions and regulator updates.")

elif page == "Control Crosswalk":
    header("02 / CONTROL INTELLIGENCE","Control Crosswalk Explorer","Explore shared control objectives and their indicative references across frameworks.")
    q1,q2,q3 = st.columns(3)
    with q1: dom = st.selectbox("Control domain",["All"]+sorted(crosswalk.domain.unique().tolist()))
    with q2: fw = st.selectbox("Framework",["All"]+sorted(crosswalk.framework.unique().tolist()))
    with q3: search = st.text_input("Search objective or reference",placeholder="e.g. privileged access")
    view=crosswalk.copy()
    if dom!="All": view=view[view.domain==dom]
    if fw!="All": view=view[view.framework==fw]
    if search:
        mask=view.astype(str).apply(lambda col: col.str.contains(search,case=False,na=False)).any(axis=1)
        view=view[mask]
    st.metric("Matching mappings",len(view))
    st.dataframe(view[["control_id","domain","control_name","framework","reference","reference_title","mapping_type","mapping_caveat"]],use_container_width=True,hide_index=True)
    st.markdown("### Mapping interpretation")
    st.markdown("""
    - **Control-level reference:** a direct control identifier is provided as a starting point.
    - **Article/theme-level mapping:** the topic is associated with a regulation provision or chapter; this is not a legal interpretation.
    - **Domain/function-level mapping:** the reference is at a broad framework level and requires detailed mapping.
    """)
    st.warning("Crosswalks are curated portfolio examples, not official equivalence statements. Verify exact text, version, scope, implementation guidance and applicability against the authoritative source before using in an audit.")


elif page == "Evidence Intelligence":
    header("03 / EVIDENCE LAB","Multi-Domain Control Audit","Select an audit domain, load a synthetic evidence population or upload an authorised CSV/XLSX file, and execute transparent control checks.")
    from core.domain_engine import analyse_domain_evidence
    domain_names=list(DOMAIN_META.keys())
    chosen=st.selectbox("Select audit domain",domain_names)
    domain_key,sample_file,description=DOMAIN_META[chosen]
    sample_path=SAMPLE_EVIDENCE_DIR/sample_file
    st.caption(description)
    left,right=st.columns([1.05,1.95],gap="large")
    with left:
        use_sample=st.checkbox("Use synthetic sample evidence",True,key="multi_sample")
        uploaded=st.file_uploader("Upload evidence population",type=["csv","xlsx"],key="multi_upload")
        st.markdown("**Audit parameters**")
        if domain_key=="iam":
            stale=st.slider("Dormant account threshold (days)",30,365,90,15)
        else:
            stale=None
        run=st.button("Run control assessment",type="primary",use_container_width=True)
        st.download_button("Download evidence template",sample_path.read_bytes(),file_name=sample_file,mime="text/csv",use_container_width=True)
        st.caption("Use synthetic or explicitly authorised data only. Do not upload employer/client confidential evidence or personal data.")
    with right:
        if uploaded or use_sample:
            try:
                evidence=load_uploaded_evidence(uploaded) if uploaded else pd.read_csv(sample_path)
                st.markdown("**Evidence population preview**")
                st.dataframe(evidence.head(15),use_container_width=True,hide_index=True)
                st.caption(f"{len(evidence):,} records · {len(evidence.columns)} fields")
                if run:
                    if domain_key=="iam":
                        result=run_iam_analysis(evidence,stale)
                    else:
                        result=analyse_domain_evidence(evidence,domain_key)
                    result["framework_context"]="Indicative mappings available in Control Crosswalk; confirm scope and exact requirements."
                    st.session_state["multi_domain_result"]=result
            except Exception as e:
                st.error(f"Unable to load evidence: {e}")
        else:
            st.info("Choose the synthetic sample or upload an authorised evidence file to begin.")
    result=st.session_state.get("multi_domain_result")
    if result and result.get("module"):
        st.markdown("---")
        st.markdown(f"### {result['module']} — assessment results")
        s=result["summary"]
        cols=st.columns(5)
        for col,label,val in zip(cols,["Population","Exceptions","Critical","High","Medium"],[result["population"],result["exception_count"],s["critical"],s["high"],s["medium"]]):
            col.metric(label,val)
        if result.get("column_mappings"):
            st.caption("Column mappings: "+" · ".join(result["column_mappings"]))
        if result.get("data_quality_issues"):
            st.warning("Data quality considerations")
            for issue in result["data_quality_issues"]: st.write("• "+issue)
        if result.get("exceptions"):
            st.dataframe(pd.DataFrame(result["exceptions"]),use_container_width=True,hide_index=True)
        else:
            st.success("No configured rule indicators identified. This does not prove control effectiveness.")
        with st.expander("Control logic, auditor validation and limitations"):
            for limitation in result.get("limitations",[]): st.write("• "+limitation)
            st.write("Every exception requires source validation, scope confirmation, control-owner discussion and auditor judgement before being classified as a finding.")
        c1,c2,c3=st.columns(3)
        with c1:
            if st.button("Save workpaper",key="save_multi"): st.success("Saved assessment: "+save_assessment(result))
        with c2:
            st.download_button("Download JSON",json.dumps(result,indent=2),file_name="technology_assessment.json",mime="application/json",use_container_width=True)
        with c3:
            st.download_button("Download Markdown",assessment_to_markdown(result),file_name="technology_assessment_workpaper.md",mime="text/markdown",use_container_width=True)

elif page == "Assessment Workpapers":
    header("04 / WORKPAPER REGISTER","Assessment Workpapers","Review previously saved local assessment records.")
    history=list_assessments()
    if history: st.dataframe(pd.DataFrame(history),use_container_width=True,hide_index=True)
    else: st.info("No saved assessments yet. Run an IAM assessment in Evidence Intelligence and save the workpaper.")
    st.caption("Assessment history is stored in a local SQLite database for this prototype. It is not an immutable audit trail.")

else:
    header("05 / PLATFORM NOTES","Platform & Methodology","Scope, architecture, source governance and limitations.")
    t1,t2,t3=st.tabs(["Architecture","Regulatory data governance","Limitations & roadmap"])
    with t1:
        st.markdown("""
        **Presentation layer** — Streamlit workspace and dashboards.

        **Evidence layer** — CSV/XLSX intake and synthetic test populations.

        **Assessment layer** — deterministic IAM rules with transparent exception logic.

        **Regulatory intelligence layer** — framework catalogue and curated crosswalk dataset.

        **Persistence layer** — local SQLite workpaper history and Markdown/JSON exports.
        """)
    with t2:
        st.markdown("""
        Every framework record includes a jurisdiction, instrument type, version label, official source and applicability note. Crosswalk records include a mapping type and caveat. A production-grade implementation should add:
        - Source document version, publication date, effective date and superseded status.
        - Requirement-level text with paragraph/article identifiers and source citations.
        - Applicability logic by entity category, geography, product, system and data type.
        - Legal/compliance review status, reviewer, approval date and mapping confidence.
        - Change monitoring and version-to-version impact analysis.
        """)
    with t3:
        st.markdown("""
        **Current capabilities:** IAM CSV/XLSX evidence analysis, framework catalogue, indicative crosswalk explorer, local workpaper history and exports.

        **Not implemented yet:** automated regulatory scraping, full-text legal interpretation, complete framework control libraries, cloud posture scanning, privacy assessments, PCI testing, AI model testing, PDF/OCR ingestion, enterprise connectors, authentication/RBAC, tenant isolation, immutable logs, evidence hashing and formal AI evaluation.

        **Important:** This is a portfolio prototype. It does not provide legal advice, an audit opinion, regulatory compliance certification or an automated control-effectiveness conclusion. Human review is mandatory.
        """)
        st.warning("Never upload employer/client confidential data or personal data. Use synthetic data or evidence you are explicitly authorised to process.")
