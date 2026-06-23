import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

df = pd.read_csv("api_security_dataset.csv")

df = df[df["protocol"] != "None"]

le = LabelEncoder()

df["protocol"] = le.fit_transform(df["protocol"])
df["method"] = le.fit_transform(df["method"])
df["severity"] = le.fit_transform(df["severity"])

X = df[
    [
        "protocol",
        "method",
        "risk_score",
        "duration"
    ]
]

pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)

kmeans = KMeans(
    n_clusters=4,
    random_state=42,
    n_init=10
)

clusters = kmeans.fit_predict(X)

plt.figure(figsize=(8,6))
plt.scatter(
    X_pca[:,0],
    X_pca[:,1],
    c=clusters
)

plt.title("KMeans Clusters using PCA")
plt.xlabel("PCA 1")
plt.ylabel("PCA 2")

plt.savefig("kmeans_pca.png")

print("Saved: kmeans_pca.png")