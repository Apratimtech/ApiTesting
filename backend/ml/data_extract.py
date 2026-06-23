from app.db.postgres import SessionLocal
from app.models.analyzer import AnalyzerScan

db = SessionLocal()

scans = db.query(AnalyzerScan).all()

print("Total scans:", len(scans))

for s in scans[:5]:
    print(
        s.id,
        s.protocol,
        s.method,
        s.severity,
        s.overall_risk_score
    )

db.close()