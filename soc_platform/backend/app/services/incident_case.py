from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.case import Case, CaseAlert, CaseTimeline
from app.models.incident import Incident
from app.services.case_number import generate_case_number
from app.services.sla import calculate_sla_dates


def default_team_for_platform(platform: str) -> str:
    if platform == "securonix":
        return "securonix_team"

    if platform == "seceon":
        return "seceon_team"

    return "soc_team"


class IncidentCaseService:
    def create_case_from_incident(
        self,
        db: Session,
        incident_id: int,
        assigned_team: str | None = None,
    ) -> Case:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        if incident.case_id:
            existing_case = (
                db.query(Case)
                .filter(Case.id == incident.case_id)
                .first()
            )

            if existing_case:
                return existing_case

        now = datetime.utcnow()
        sla_dates = calculate_sla_dates(incident.priority, now)

        case = Case(
            case_number=generate_case_number(db),
            tenant_id=incident.tenant_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            priority=incident.priority,
            status="new",
            assigned_team=assigned_team or default_team_for_platform(incident.platform),
            source_platform_summary=incident.platform,
            first_alert_time=incident.first_seen_at or incident.created_at,
            last_activity_time=now,
            ack_due_at=sla_dates["ack_due_at"],
            escalation_due_at=sla_dates["escalation_due_at"],
            resolution_due_at=sla_dates["resolution_due_at"],
        )

        db.add(case)
        db.commit()
        db.refresh(case)

        incident.case_id = case.id

        if incident.alert_id:
            alert = (
                db.query(Alert)
                .filter(Alert.id == incident.alert_id)
                .first()
            )

            if alert:
                alert.case_id = case.id

                existing_link = (
                    db.query(CaseAlert)
                    .filter(
                        CaseAlert.case_id == case.id,
                        CaseAlert.alert_id == alert.id,
                    )
                    .first()
                )

                if not existing_link:
                    link = CaseAlert(
                        case_id=case.id,
                        alert_id=alert.id,
                        linked_reason="case_created_from_incident",
                    )
                    db.add(link)

        timeline = CaseTimeline(
            case_id=case.id,
            event_type="case_created_from_incident",
            event_title="Case created from unified incident",
            event_description=(
                f"Case created from {incident.platform} incident "
                f"{incident.source_incident_id}."
            ),
            actor_type="system",
        )

        db.add(timeline)
        db.commit()
        db.refresh(case)

        return case


incident_case_service = IncidentCaseService()