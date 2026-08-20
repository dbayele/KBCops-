# KBCops-

A minimal Police Records Management System foundation focused on IACP CJIS Committee and IJIS LEAC-aligned controls.

## What is included

- `police_rms.py`: in-memory RMS core with:
  - multi-factor authentication (MFA) requirement on all operations
  - role-based access control (RBAC)
  - agency-scope isolation for records
  - sealed-record access restrictions
  - append-only operation audit logging
  - record classification and retention metadata
- `tests/test_police_rms.py`: focused unit tests for the compliance-critical behavior above.

## Quick test

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## Compliance mapping (implemented controls)

- **CJIS identity & access**: MFA and RBAC checks at the service layer.
- **CJIS audit & accountability**: all read/write/seal operations create audit entries with user, role, timestamp, and record ID.
- **CJIS data governance**: classification and retention period assigned during record creation.
- **LEAC interoperability readiness**: incident-focused schema fields (`incident_number`, `offense_code`, `classification`) prepared for standards-based exchange.
- **LEAC privacy controls**: sealed records constrained to authorized personnel.

> Note: This repository now contains a secure RMS baseline. Production deployment still requires infrastructure controls (encryption at rest/in transit, key management, secure hosting, monitoring, and formal policy/process controls) to achieve full organizational compliance.
