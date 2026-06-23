import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier


df = pd.read_csv("api_security_dataset.csv")

df = df[df["protocol"] != "None"]

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

importance = model.feature_importances_

features = [
    "protocol",
    "method",
    "risk_score",
    "duration"
]

for f, i in zip(features, importance):
    print(f, round(i, 4))

plt.figure(figsize=(8, 5))
plt.bar(features, importance)

plt.title("Random Forest Feature Importance")
plt.xlabel("Features")
plt.ylabel("Importance")

plt.savefig("feature_importance.png")

with open("feature_importance.txt", "w") as file:
    file.write("RANDOM FOREST FEATURE IMPORTANCE\n\n")

    for f, i in zip(features, importance):
        file.write(f"{f}: {round(i,4)}\n")

print("\nSaved:")
print("feature_importance.png")
print("feature_importance.txt")