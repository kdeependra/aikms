"""
AIKMS AI/ML Service
Detects anomalous key usage patterns via an Isolation Forest model.
Publishes anomaly alerts to the anomaly-events Kafka topic.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import asyncio
import logging

from config import Settings
from kafka_consumer import start_consumer
from routers import health, anomaly

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start Kafka consumer in background
    consumer_task = asyncio.create_task(start_consumer(settings))
    logger.info("AIKMS AI/ML service started")
    yield
    consumer_task.cancel()
    logger.info("AIKMS AI/ML service stopped")


app = FastAPI(
    title="AIKMS AI/ML Service",
    version="1.0.0",
    description="Anomaly detection for key usage events",
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(anomaly.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.server_port)
