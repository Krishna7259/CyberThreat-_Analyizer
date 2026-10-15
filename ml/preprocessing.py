import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

# Primary UNSW-NB15 Feature Definitions
NUMERICAL_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
    'smean', 'dmean', 'trans_depth', 'response_body_len'
]

CATEGORICAL_FEATURES = [
    'proto', 'service', 'state'
]

ALL_FEATURE_COLUMNS = NUMERICAL_FEATURES + CATEGORICAL_FEATURES
TARGET_COLUMN = 'label'  # 0 = Normal, 1 = Attack / Suspicious
CATEGORY_COLUMN = 'attack_cat'  # Specific threat category

def validate_dataset_schema(df: pd.DataFrame):
    """
    Validates whether an uploaded DataFrame contains the mandatory schema.
    Returns: (is_valid: bool, missing_columns: list, message: str)
    """
    if not isinstance(df, pd.DataFrame) or df.empty:
        return False, [], "Dataset is empty or could not be parsed."

    # Standardize column names to lower case and stripped
    cols = [str(c).strip().lower() for c in df.columns]
    
    missing_cols = [col for col in ALL_FEATURE_COLUMNS if col not in cols]
    
    # Allow partial tolerance if at least key features exist, but mandate primary features
    essential_features = ['dur', 'sbytes', 'dbytes', 'rate', 'sttl', 'proto', 'service', 'state']
    missing_essentials = [col for col in essential_features if col not in cols]
    
    if missing_essentials:
        return False, missing_essentials, f"Incompatible schema. Missing essential columns: {', '.join(missing_essentials)}"
        
    return True, missing_cols, "Dataset schema is compatible with UNSW-NB15 specifications."

def clean_and_prepare_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans column names, handles missing feature columns with default zeros,
    and strips string columns.
    """
    df_clean = df.copy()
    df_clean.columns = [str(c).strip().lower() for c in df_clean.columns]
    
    # Fill any missing required numerical columns with 0
    for col in NUMERICAL_FEATURES:
        if col not in df_clean.columns:
            df_clean[col] = 0.0
        else:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce').fillna(0.0)
            
    # Fill any missing categorical columns with '-'
    for col in CATEGORICAL_FEATURES:
        if col not in df_clean.columns:
            df_clean[col] = '-'
        else:
            df_clean[col] = df_clean[col].astype(str).str.strip().fillna('-')
            
    return df_clean

def build_preprocessing_pipeline():
    """
    Constructs a ColumnTransformer for numerical scaling and categorical one-hot encoding.
    """
    num_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    
    cat_pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='constant', fill_value='-')),
        ('encoder', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', num_pipeline, NUMERICAL_FEATURES),
            ('cat', cat_pipeline, CATEGORICAL_FEATURES)
        ],
        remainder='drop'
    )
    return preprocessor
