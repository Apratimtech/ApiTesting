import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib


df = pd.read_csv("api_security_dataset.csv")

# remove missing protocol rows
df = df[df["protocol"] != "None"]


# convert text columns
encoder = LabelEncoder()

df["protocol"] = encoder.fit_transform(df["protocol"])
df["method"] = encoder.fit_transform(df["method"])
df["severity"] = encoder.fit_transform(df["severity"])


X = df[
    [
        "protocol",
        "method",
        "risk_score",
        "duration"
    ]
]

# target
y = df["severity"]


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


model.fit(X_train, y_train)


pred = model.predict(X_test)


print("Accuracy:", accuracy_score(y_test, pred))
print(classification_report(y_test, pred))


joblib.dump(model, "risk_model.pkl")

print("Model saved!")