from datetime import datetime

from sqlalchemy.orm import Session

from app.models.case import Case


def generate_case_number(db: Session) -> str:
    today = datetime.utcnow().strftime("%Y%m%d")

    count_today = (
        db.query(Case)
        .filter(Case.case_number.like(f"CASE-{today}-%"))
        .count()
    )

    sequence = count_today + 1

    return f"CASE-{today}-{sequence:05d}"