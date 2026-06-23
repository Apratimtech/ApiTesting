import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, accuracy_score

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
    random_state=42
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)

cm = confusion_matrix(y_test, pred)

print("Accuracy:", accuracy)
print("\nConfusion Matrix:")
print(cm)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm
)

disp.plot()

plt.savefig(
    "decision_tree_confusion_matrix.png",
    bbox_inches="tight"
)

with open(
    "decision_tree_confusion_results.txt",
    "w"
) as f:

    f.write(
        f"Decision Tree Accuracy: {accuracy:.4f}\n"
    )

print("Saved:")
print("decision_tree_confusion_matrix.png")
print("decision_tree_confusion_results.txt")