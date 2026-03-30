from fastapi import APIRouter

router = APIRouter(prefix="/api/anomaly", tags=["anomaly"])


@router.get("/status")
def status():
    """Returns operational status of the anomaly detection pipeline."""
    return {"status": "running", "model": "IsolationForest"}
