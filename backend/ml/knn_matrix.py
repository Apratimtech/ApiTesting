import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.neighbors import KNeighborsClassifier
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

model = KNeighborsClassifier(
    n_neighbors=5
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

accuracy = accuracy_score(y_test, pred)

cm = confusion_matrix(y_test, pred)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm
)

disp.plot()

plt.title("KNN Confusion Matrix")

plt.savefig("knn_confusion_matrix.png")

with open("knn_results.txt", "w") as file:
    file.write("KNN RESULTS\n\n")
    file.write(f"Accuracy: {accuracy:.4f}\n\n")
    file.write("Algorithm Type: Supervised Classification\n")
    file.write("Purpose: Predict API Severity Levels\n")

print("Accuracy:", accuracy)
print("Saved:")
print("knn_confusion_matrix.png")
print("knn_results.txt")