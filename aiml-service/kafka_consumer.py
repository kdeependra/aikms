"""
Kafka consumer: reads key-usage-events, scores each event through the
anomaly detector, and publishes high-score events to anomaly-events.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer

from config import Settings
from models.anomaly_detector import AnomalyDetector

logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = 0.65


async def start_consumer(settings: Settings) -> None:
    detector = AnomalyDetector(contamination=settings.anomaly_contamination)

    consumer = KafkaConsumer(
        settings.kafka_usage_topic,
        bootstrap_servers=settings.kafka_brokers,
        group_id=settings.kafka_consumer_group,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )

    producer = KafkaProducer(
        bootstrap_servers=settings.kafka_brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
    )

    logger.info("Kafka consumer started, listening on %s", settings.kafka_usage_topic)

    loop = asyncio.get_event_loop()

    while True:
        try:
            records = await loop.run_in_executor(
                None, lambda: consumer.poll(timeout_ms=1000, max_records=100)
            )
            for tp, messages in records.items():
                for msg in messages:
                    await _process_event(msg.value, detector, producer, settings)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Consumer error: %s", exc, exc_info=True)
            await asyncio.sleep(5)

    consumer.close()
    producer.close()


async def _process_event(event: dict, detector: AnomalyDetector,
                         producer: KafkaProducer, settings: Settings) -> None:
    key_id    = event.get("keyId", "unknown")
    operation = event.get("operation", "UNKNOWN")
    success   = event.get("success", True)
    ts_str    = event.get("occurredAt")

    try:
        ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)

    detector.record_event(key_id, operation, success, ts)
    score = detector.predict(key_id, operation, success, ts)

    if score >= ANOMALY_THRESHOLD:
        logger.warning("Anomaly detected: keyId=%s operation=%s score=%.3f", key_id, operation, score)
        anomaly_event = {
            "anomalyId":   __import__("uuid").uuid4().hex,
            "keyId":       key_id,
            "namespaceId": event.get("namespaceId"),
            "operation":   operation,
            "actorId":     event.get("actorId"),
            "score":       score,
            "detectedAt":  datetime.now(timezone.utc).isoformat(),
            "details":     f"Anomaly score {score:.3f} exceeds threshold {ANOMALY_THRESHOLD}",
        }
        producer.send(settings.kafka_anomaly_topic, value=anomaly_event)
