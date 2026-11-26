from io import BytesIO
import pandas as pd
def load_uploaded_evidence(uploaded):
    name=uploaded.name.lower(); raw=uploaded.getvalue()
    if name.endswith(".csv"): return pd.read_csv(BytesIO(raw))
    if name.endswith(".xlsx"): return pd.read_excel(BytesIO(raw))
    raise ValueError("This release supports CSV and XLSX.")
