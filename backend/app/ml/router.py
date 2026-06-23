from fastapi import APIRouter
import joblib
import pandas as pd

router = APIRouter(
    prefix="/ml",
    tags=["ML Analysis"]
)

model = joblib.load("risk_model.pkl")


@router.get("/status")
def ml_status():
    return {
        "success": True,
        "message": "ML module active"
    }


@router.post("/predict")
def predict(data: dict):

    df = pd.DataFrame([data])

    prediction = model.predict(df)[0]

    return {
        "success": True,
        "predicted_severity": int(prediction)
    }