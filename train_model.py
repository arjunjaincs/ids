# ------------------------------------------------------------
# 🧠 train_model.py
# Random Forest Training for IDS Packet Classification
# Intel Unnati IDS | Author: Arjun | Version: 1.0
# ------------------------------------------------------------

import pandas as pd
import joblib
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# ------------------------------------------------------------
# 📥 Load Dataset
# ------------------------------------------------------------

df = pd.read_csv("csv/final_processed.csv")

# ------------------------------------------------------------
# 🎯 Split Features & Labels
# ------------------------------------------------------------

X = df.drop(columns=["label"])
y = df["label"]

# ------------------------------------------------------------
# 🧪 Train/Test Split (Stratified)
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ------------------------------------------------------------
# 🔧 Train Model
# ------------------------------------------------------------

print("🔧 Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    class_weight="balanced",
    n_jobs=-1
)
model.fit(X_train, y_train)

# ------------------------------------------------------------
# 💾 Save Model
# ------------------------------------------------------------

joblib.dump(model, "data/ids_model.pkl")
print("✅ Model saved to: data/ids_model.pkl")

# ------------------------------------------------------------
# 📊 Evaluate Model
# ------------------------------------------------------------

y_pred = model.predict(X_test)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred))

# ------------------------------------------------------------
# 📈 Confusion Matrix
# ------------------------------------------------------------

cm = confusion_matrix(y_test, y_pred)
sns.heatmap(
    cm, annot=True, fmt="d", cmap="coolwarm",
    xticklabels=["Normal", "Attack"],
    yticklabels=["Normal", "Attack"]
)
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("data/confusion_matrix.png")
print("📈 Confusion matrix saved to: data/confusion_matrix.png")
