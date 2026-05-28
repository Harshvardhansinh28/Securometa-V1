import json
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class RedpandaProducer:
    def __init__(self) -> None:
        self.enabled = settings.redpanda_enabled
        self.producer = None

        if not self.enabled:
            logger.warning("Redpanda publishing is disabled")
            return

        try:
            from confluent_kafka import Producer

            self.producer = Producer(
                {
                    "bootstrap.servers": settings.redpanda_bootstrap_servers,
                    "client.id": "soc-platform-backend",
                    "enable.idempotence": True,
                    "acks": "all",
                }
            )

        except Exception as exc:
            self.enabled = False
            self.producer = None
            logger.exception("Redpanda producer initialization failed: %s", exc)

    def publish(
        self,
        topic: str,
        key: str,
        value: dict[str, Any],
    ) -> None:
        if not self.enabled or self.producer is None:
            return

        try:
            self.producer.produce(
                topic=topic,
                key=key.encode("utf-8"),
                value=json.dumps(value, default=str).encode("utf-8"),
            )

            self.producer.poll(0)

        except Exception as exc:
            logger.exception("Failed to publish event to Redpanda: %s", exc)

    def flush(self) -> None:
        if self.enabled and self.producer is not None:
            self.producer.flush()


redpanda_producer = RedpandaProducer()