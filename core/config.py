from pathlib import Path
BASE_DIR=Path(__file__).resolve().parent.parent
APP_NAME="AI-Powered Technology Assurance Copilot"
CONTROL_LIBRARY_PATH=BASE_DIR/"data"/"control_library.csv"
SAMPLE_EVIDENCE_DIR=BASE_DIR/"sample_evidence"
DB_PATH=BASE_DIR/"data"/"assessments.db"
