import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("api_security_dataset.csv")

df = df[df["protocol"] != "None"]

# Protocol count
df["protocol"].value_counts().plot(kind="bar")
plt.title("API Protocol Distribution")
plt.xlabel("Protocol")
plt.ylabel("Count")
plt.savefig("protocol_distribution.png")
plt.close()


# Severity count
df["severity"].value_counts().plot(kind="bar")
plt.title("Security Severity Distribution")
plt.xlabel("Severity")
plt.ylabel("Count")
plt.savefig("severity_distribution.png")
plt.close()


# Risk score
df["risk_score"].plot(kind="hist", bins=10)
plt.title("Risk Score Distribution")
plt.xlabel("Risk Score")
plt.savefig("risk_distribution.png")
plt.close()


print("Visualizations generated!")