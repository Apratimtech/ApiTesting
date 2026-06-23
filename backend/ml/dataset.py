import pandas as pd
from app.db.postgres import SessionLocal
from app.models.analyzer import AnalyzerScan

db = SessionLocal()

scans = db.query(AnalyzerScan).all()

data = []

for s in scans:
    data.append({
        "protocol": str(s.protocol),
        "method": s.method,
        "risk_score": s.overall_risk_score,
        "severity": str(s.severity),
        "duration": s.duration_ms or 0
    })

db.close()

df = pd.DataFrame(data)

df = df.dropna()

print(df.head())
print("\nDataset size:", df.shape)

df.to_csv("api_security_dataset.csv", index=False)

print("\nDataset saved!")