import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.metrics import accuracy_score


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

model = DecisionTreeClassifier(
    random_state=42,
    max_depth=3
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)

plt.figure(figsize=(14, 8))

plot_tree(
    model,
    feature_names=[
        "protocol",
        "method",
        "risk_score",
        "duration"
    ],
    filled=True,
    rounded=True,
    fontsize=8
)

plt.title("Decision Tree for API Severity Prediction")

plt.savefig("decision_tree.png")

with open("decision_tree_results.txt", "w") as file:
    file.write("DECISION TREE RESULTS\n\n")
    file.write(f"Accuracy: {accuracy:.4f}\n\n")
    file.write("Features Used:\n")
    file.write("- protocol\n")
    file.write("- method\n")
    file.write("- risk_score\n")
    file.write("- duration\n")

print("Accuracy:", accuracy)
print("Saved:")
print("decision_tree.png")
print("decision_tree_results.txt")