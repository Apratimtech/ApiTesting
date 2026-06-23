import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
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

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Decision Tree": DecisionTreeClassifier(random_state=42),
    "KNN": KNeighborsClassifier(n_neighbors=5),
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
}

results = {}

print("\nMODEL COMPARISON\n")

for name, model in models.items():

    model.fit(X_train, y_train)

    pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, pred)

    results[name] = accuracy

    print(f"{name}: {accuracy:.4f}")

with open("model_results.txt", "w") as f:

    f.write("MODEL COMPARISON\n\n")

    for name, accuracy in results.items():
        f.write(f"{name}: {accuracy:.4f}\n")

plt.figure(figsize=(8,5))

plt.bar(
    list(results.keys()),
    list(results.values())
)

plt.ylabel("Accuracy")
plt.title("Model Accuracy Comparison")

plt.tight_layout()

plt.savefig("model_accuracy.png")

print("\nSaved:")
print("model_accuracy.png")
print("model_results.txt")