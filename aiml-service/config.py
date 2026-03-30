from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    kafka_brokers: str = "localhost:9092"
    kafka_consumer_group: str = "aiml-service"
    kafka_usage_topic: str = "key-usage-events"
    kafka_anomaly_topic: str = "anomaly-events"
    server_port: int = 8086
    anomaly_contamination: float = 0.05   # 5% expected anomaly rate
    model_retrain_interval_secs: int = 3600

    class Config:
        env_file = ".env"
