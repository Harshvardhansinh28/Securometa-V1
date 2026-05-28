import hashlib
import json
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.incident import ThreatIndicator
from app.services.raw_payload_store import raw_payload_store


def hash_indicator_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_indicator_type(value: str | None) -> str:
    if not value:
        return "unknown"

    text = str(value).lower().strip()

    if text in {"ip", "ipv4", "ipv6", "ip_address"}:
        return "ip"

    if text in {"domain", "fqdn", "hostname"}:
        return "domain"

    if text in {"url", "uri"}:
        return "url"

    if text in {"hash", "md5", "sha1", "sha256"}:
        return "hash"

    return text


class ThreatIndicatorStore:
    def store_from_response(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
        incident_id: int,
        incident_event_id: int | None,
        source_event_id: str,
        response_payload: dict[str, Any],
    ) -> int:
        raw_payload = raw_payload_store.store(
            db=db,
            tenant_id=tenant_id,
            platform=platform,
            object_type="threat_indicator_response",
            source_object_id=source_event_id,
            raw_json=response_payload,
        )

        indicators = self._extract_indicators(response_payload)

        stored_count = 0

        for indicator in indicators:
            indicator_type = normalize_indicator_type(indicator.get("indicator_type"))
            indicator_value = str(indicator.get("indicator_value") or "").strip()

            if not indicator_value:
                continue

            indicator_hash = hash_indicator_value(indicator_value)

            existing = (
                db.query(ThreatIndicator)
                .filter(
                    ThreatIndicator.tenant_id == tenant_id,
                    ThreatIndicator.indicator_type == indicator_type,
                    ThreatIndicator.indicator_value_hash == indicator_hash,
                    ThreatIndicator.source == indicator.get("source"),
                )
                .first()
            )

            if existing:
                existing.incident_id = incident_id
                existing.incident_event_id = incident_event_id
                existing.category = indicator.get("category")
                existing.reputation = indicator.get("reputation")
                existing.confidence = indicator.get("confidence")
                existing.raw_payload_id = raw_payload.id

                db.commit()
                stored_count += 1
                continue

            record = ThreatIndicator(
                incident_id=incident_id,
                incident_event_id=incident_event_id,
                tenant_id=tenant_id,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                indicator_value_hash=indicator_hash,
                source=indicator.get("source"),
                category=indicator.get("category"),
                reputation=indicator.get("reputation"),
                confidence=indicator.get("confidence"),
                raw_payload_id=raw_payload.id,
            )

            db.add(record)

            try:
                db.commit()
                stored_count += 1

            except IntegrityError:
                db.rollback()

        return stored_count

    def _extract_indicators(
        self,
        payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Supports multiple possible Seceon response shapes.

        Example possible structures:
        {
          "response": [...]
        }

        {
          "data": [...]
        }

        {
          "threatIndicators": [...]
        }

        {
          "indicator_type": "...",
          "indicator_value": "..."
        }
        """

        candidates = []

        for key in [
            "response",
            "data",
            "threatIndicators",
            "threat_indicators",
            "indicators",
            "result",
        ]:
            value = payload.get(key)

            if isinstance(value, list):
                candidates.extend(value)

            elif isinstance(value, dict):
                nested = self._extract_indicators(value)
                candidates.extend(nested)

        if not candidates:
            if self._looks_like_indicator(payload):
                candidates.append(payload)

        normalized = []

        for item in candidates:
            if not isinstance(item, dict):
                continue

            indicator_type = (
                item.get("indicator_type")
                or item.get("indicatorType")
                or item.get("type")
                or item.get("ioc_type")
                or item.get("iocType")
                or item.get("category")
            )

            indicator_value = (
                item.get("indicator_value")
                or item.get("indicatorValue")
                or item.get("value")
                or item.get("ioc")
                or item.get("observable")
                or item.get("threat_indicator")
            )

            if not indicator_value:
                continue

            normalized.append(
                {
                    "indicator_type": indicator_type or "unknown",
                    "indicator_value": indicator_value,
                    "source": item.get("source") or item.get("provider") or "seceon",
                    "category": item.get("category") or item.get("threatCategory"),
                    "reputation": item.get("reputation") or item.get("verdict"),
                    "confidence": self._safe_float(
                        item.get("confidence")
                        or item.get("score")
                        or item.get("confidence_score")
                    ),
                }
            )

        return normalized

    def _looks_like_indicator(self, payload: dict[str, Any]) -> bool:
        possible_value_keys = {
            "indicator_value",
            "indicatorValue",
            "value",
            "ioc",
            "observable",
            "threat_indicator",
        }

        return any(key in payload for key in possible_value_keys)

    def _safe_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None


threat_indicator_store = ThreatIndicatorStore()