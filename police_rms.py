from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
import uuid


class AccessDenied(Exception):
    """Raised when a user is not authorized for an operation."""


class ValidationError(Exception):
    """Raised when a record payload is invalid."""


@dataclass(frozen=True)
class UserContext:
    user_id: str
    role: str
    agency_id: str
    mfa_authenticated: bool


class PoliceRMS:
    """Minimal police records system with CJIS/LEAC-oriented safeguards."""

    _CREATE_ROLES = {"records_officer", "detective", "admin"}
    _READ_ROLES = {"records_officer", "detective", "patrol", "auditor", "admin"}
    _UPDATE_ROLES = {"records_officer", "detective", "admin"}
    _AUDIT_ROLES = {"auditor", "admin"}
    _SEALED_READ_ROLES = {"records_officer", "admin"}
    _CLASSIFICATIONS = {"criminal_incident", "arrest", "citation", "evidence"}

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        self._audit_events: list[dict[str, Any]] = []

    def create_record(
        self,
        user: UserContext,
        *,
        incident_number: str,
        subject_name: str,
        offense_code: str,
        narrative: str,
        classification: str,
        retention_days: int = 2555,
    ) -> str:
        self._require_mfa(user)
        self._require_role(user, self._CREATE_ROLES)
        if classification not in self._CLASSIFICATIONS:
            raise ValidationError("Unsupported classification")
        if not incident_number.strip() or not subject_name.strip() or not offense_code.strip():
            raise ValidationError("Incident number, subject name, and offense code are required")

        now = datetime.now(timezone.utc)
        record_id = str(uuid.uuid4())
        self._records[record_id] = {
            "id": record_id,
            "agency_id": user.agency_id,
            "incident_number": incident_number,
            "subject_name": subject_name,
            "offense_code": offense_code,
            "narrative": narrative,
            "classification": classification,
            "created_at": now.isoformat(),
            "created_by": user.user_id,
            "updated_at": now.isoformat(),
            "updated_by": user.user_id,
            "sealed": False,
            "retention_until": (now + timedelta(days=retention_days)).isoformat(),
            "version": 1,
        }
        self._audit("create_record", user, record_id)
        return record_id

    def view_record(self, user: UserContext, record_id: str) -> dict[str, Any]:
        self._require_mfa(user)
        self._require_role(user, self._READ_ROLES)
        record = self._get_record(record_id)
        self._enforce_agency_scope(user, record)
        if record["sealed"] and user.role not in self._SEALED_READ_ROLES:
            raise AccessDenied("Sealed records require records_officer/admin access")
        self._audit("view_record", user, record_id)
        return dict(record)

    def update_narrative(self, user: UserContext, record_id: str, narrative: str) -> None:
        self._require_mfa(user)
        self._require_role(user, self._UPDATE_ROLES)
        record = self._get_record(record_id)
        self._enforce_agency_scope(user, record)

        record["narrative"] = narrative
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        record["updated_by"] = user.user_id
        record["version"] += 1
        self._audit("update_narrative", user, record_id)

    def seal_record(self, user: UserContext, record_id: str) -> None:
        self._require_mfa(user)
        self._require_role(user, {"records_officer", "admin"})
        record = self._get_record(record_id)
        self._enforce_agency_scope(user, record)
        record["sealed"] = True
        self._audit("seal_record", user, record_id)

    def audit_trail(self, user: UserContext, *, record_id: str | None = None) -> list[dict[str, Any]]:
        self._require_mfa(user)
        self._require_role(user, self._AUDIT_ROLES)
        if record_id is None:
            return [dict(event) for event in self._audit_events]
        return [dict(event) for event in self._audit_events if event["record_id"] == record_id]

    @staticmethod
    def compliance_profile() -> dict[str, str]:
        return {
            "cjis_identity_and_access": "MFA gate and role-based authorization enforced for all operations.",
            "cjis_audit_accountability": "Immutable operation-level audit trail (create/view/update/seal) with UTC timestamps.",
            "cjis_data_governance": "Record classification and retention windows are enforced at creation time.",
            "leac_information_sharing": "Record schema includes incident/offense fields to support standards-based exchange pipelines.",
            "leac_privacy_controls": "Sealed record handling enforces constrained visibility for sensitive cases.",
        }

    def _get_record(self, record_id: str) -> dict[str, Any]:
        record = self._records.get(record_id)
        if record is None:
            raise ValidationError("Record not found")
        return record

    def _require_role(self, user: UserContext, allowed_roles: set[str]) -> None:
        if user.role not in allowed_roles:
            raise AccessDenied("User role is not authorized for this operation")

    @staticmethod
    def _require_mfa(user: UserContext) -> None:
        if not user.mfa_authenticated:
            raise AccessDenied("MFA authentication is required")

    @staticmethod
    def _enforce_agency_scope(user: UserContext, record: dict[str, Any]) -> None:
        if user.role == "admin":
            return
        if user.agency_id != record["agency_id"]:
            raise AccessDenied("Cross-agency record access is not allowed")

    def _audit(self, action: str, user: UserContext, record_id: str) -> None:
        self._audit_events.append(
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "user_id": user.user_id,
                "role": user.role,
                "agency_id": user.agency_id,
                "record_id": record_id,
            }
        )
