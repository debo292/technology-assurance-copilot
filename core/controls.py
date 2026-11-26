import pandas as pd
def load_controls(path):
    return pd.read_csv(path).fillna("").to_dict(orient="records")
