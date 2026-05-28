from datetime import datetime, timedelta


SLA_MATRIX = {
    "P1": {
        "ack_minutes": 15,
        "escalation_minutes": 30,
        "resolution_minutes": 240,
    },
    "P2": {
        "ack_minutes": 30,
        "escalation_minutes": 60,
        "resolution_minutes": 480,
    },
    "P3": {
        "ack_minutes": 240,
        "escalation_minutes": 480,
        "resolution_minutes": 1440,
    },
    "P4": {
        "ack_minutes": 1440,
        "escalation_minutes": 2880,
        "resolution_minutes": 4320,
    },
    "P5": {
        "ack_minutes": 2880,
        "escalation_minutes": 4320,
        "resolution_minutes": 10080,
    },
}


def calculate_sla_dates(priority: str, start_time: datetime | None = None) -> dict:
    now = start_time or datetime.utcnow()

    sla = SLA_MATRIX.get(priority.upper(), SLA_MATRIX["P3"])

    return {
        "ack_due_at": now + timedelta(minutes=sla["ack_minutes"]),
        "escalation_due_at": now + timedelta(minutes=sla["escalation_minutes"]),
        "resolution_due_at": now + timedelta(minutes=sla["resolution_minutes"]),
    }