import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import joblib
import sys

# Load all datasets (NHANES 2017–2018 versions)
demographics = pd.read_csv("DEMO.csv")
examination = pd.read_csv("BMX.csv")
diabetes = pd.read_csv("DIQ.csv")
glucose = pd.read_csv("glucose_data.csv")
bp = pd.read_csv("BPX.csv")  # ✅ Blood pressure data

# Merge everything using SEQN
df = demographics.merge(diabetes, on="SEQN") \
                 .merge(examination, on="SEQN") \
                 .merge(glucose[['SEQN', 'LBXGLU']], on="SEQN") \
                 .merge(bp[['SEQN', 'BPXSY1', 'BPXDI1']], on="SEQN")

# Check merge result
print("✅ Merged shape:", df.shape)
print("🔍 Missing values:\n", df[['RIAGENDR', 'RIDAGEYR', 'DIQ010', 'BMXBMI', 'LBXGLU', 'BPXSY1', 'BPXDI1']].isna().sum())
print("🔍 DIQ010 unique values:", df['DIQ010'].unique())

# Select required columns
df = df[['RIAGENDR', 'RIDAGEYR', 'DIQ010', 'BMXBMI', 'BPXSY1', 'BPXDI1', 'LBXGLU']]
df = df.dropna()

# Filter only valid labels: 1 = diabetic, 2 = non-diabetic
df = df[df['DIQ010'].isin([1, 2])]
df['diabetes'] = df['DIQ010'].replace({1: 1, 2: 0})

# Early exit if empty
if df.empty:
    print("🚫 ERROR: No data after filtering.")
    sys.exit(1)

# Show class distribution
print("✅ Class distribution:\n", df['diabetes'].value_counts())

# Features and target
X = df[['RIAGENDR', 'RIDAGEYR', 'BMXBMI', 'BPXSY1', 'BPXDI1', 'LBXGLU']]
y = df['diabetes']

# Scale
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Handle imbalance
ratio = y_train.value_counts()[0] / y_train.value_counts()[1]

# Train model
model = XGBClassifier(
    use_label_encoder=False,
    eval_metric='logloss',
    scale_pos_weight=ratio,
    n_estimators=200,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("🎯 Accuracy:", accuracy_score(y_test, y_pred))

# Save model and scaler
joblib.dump(model, "xgb_diabetes_model.joblib")
joblib.dump(scaler, "scaler.joblib")
print("✅ Model and scaler saved.")
