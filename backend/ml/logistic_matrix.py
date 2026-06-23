import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)

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

model = LogisticRegression(
    max_iter=2000
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)

cm = confusion_matrix(y_test, pred)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm
)

disp.plot()

plt.title("Logistic Regression Confusion Matrix")

plt.savefig("logistic_confusion_matrix.png")

with open("logistic_results.txt", "w") as file:
    file.write("LOGISTIC REGRESSION RESULTS\n\n")
    file.write(f"Accuracy: {accuracy:.4f}\n\n")
    file.write("Algorithm Type: Supervised Classification\n")
    file.write("Purpose: Predict API Severity Levels\n")

print("Accuracy:", accuracy)
print("Saved:")
print("logistic_confusion_matrix.png")
print("logistic_results.txt")