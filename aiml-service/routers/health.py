from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health():
    return {"status": "UP", "service": "aiml-service"}
