"""Case endpoints: the analyst's investigation workflow unit (ui-design §4.4).

A case groups evidence objects under a title / severity / status and
collects analyst notes. Status flow: new -> investigating -> contained ->
resolved -> closed.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import Case, CaseEvidence, CaseNote, EvidenceObject, User
from argus.infrastructure.db.session import tenant_session

router = APIRouter(prefix="/cases", tags=["cases"])

Status = Literal["new", "investigating", "contained", "resolved", "closed"]
Severity = Literal["critical", "high", "medium", "low"]


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


class CaseOut(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    assignee_email: str | None
    evidence_count: int
    created_at: datetime
    updated_at: datetime


class CaseListOut(BaseModel):
    items: list[CaseOut]
    total: int


class EvidenceBrief(BaseModel):
    id: int
    host_name: str | None
    score: int
    technique_ids: list[str]
    window_end: datetime
    status: str

    model_config = {"from_attributes": True}


class NoteOut(BaseModel):
    id: int
    author_email: str | None
    body: str
    created_at: datetime


class CaseDetailOut(CaseOut):
    description: str | None
    evidence: list[EvidenceBrief]
    notes: list[NoteOut]


class CaseCreateIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    severity: Severity | None = None
    evidence_ids: list[int] = Field(default_factory=list, max_length=50)


class CaseUpdateIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    severity: Severity | None = None
    status: Status | None = None


class AttachEvidenceIn(BaseModel):
    evidence_id: int


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


async def _user_emails(session, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not user_ids:
        return {}
    rows = (await session.scalars(select(User).where(User.id.in_(user_ids)))).all()
    return {u.id: u.email for u in rows}


def _case_out(case: Case, assignee_email: str | None, evidence_count: int) -> CaseOut:
    return CaseOut(
        id=case.id,
        title=case.title,
        severity=case.severity,
        status=case.status,
        assignee_email=assignee_email,
        evidence_count=evidence_count,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


@router.get("", response_model=CaseListOut)
async def list_cases(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    status: Annotated[Status | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CaseListOut:
    filters = []
    if status is not None:
        filters.append(Case.status == status)

    async with tenant_session(current.tenant_id) as s:
        total = await s.scalar(select(func.count(Case.id)).where(*filters)) or 0
        cases = (
            await s.scalars(
                select(Case)
                .where(*filters)
                .order_by(Case.updated_at.desc(), Case.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        counts = dict(
            (
                await s.execute(
                    select(CaseEvidence.case_id, func.count())
                    .where(CaseEvidence.case_id.in_([c.id for c in cases] or [0]))
                    .group_by(CaseEvidence.case_id)
                )
            ).all()
        )
        emails = await _user_emails(s, {c.assignee_user_id for c in cases if c.assignee_user_id})

    return CaseListOut(
        items=[
            _case_out(c, emails.get(c.assignee_user_id), counts.get(c.id, 0)) for c in cases
        ],
        total=total,
    )


@router.post("", response_model=CaseDetailOut, status_code=201)
async def create_case(
    body: CaseCreateIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CaseDetailOut:
    async with tenant_session(current.tenant_id) as s:
        evidence: list[EvidenceObject] = []
        if body.evidence_ids:
            evidence = (
                await s.scalars(
                    select(EvidenceObject).where(EvidenceObject.id.in_(body.evidence_ids))
                )
            ).all()
            missing = set(body.evidence_ids) - {e.id for e in evidence}
            if missing:
                raise HTTPException(404, f"Evidence not found: {sorted(missing)}")

        severity = body.severity or (
            _severity_from_score(max(e.score for e in evidence)) if evidence else "medium"
        )
        case = Case(
            tenant_id=current.tenant_id,
            title=body.title,
            description=body.description,
            severity=severity,
            assignee_user_id=current.user_id,
        )
        s.add(case)
        await s.flush()
        for e in evidence:
            s.add(
                CaseEvidence(case_id=case.id, evidence_id=e.id, tenant_id=current.tenant_id)
            )
        await s.flush()
        emails = await _user_emails(s, {current.user_id})
        return CaseDetailOut(
            **_case_out(case, emails.get(current.user_id), len(evidence)).model_dump(),
            description=case.description,
            evidence=[EvidenceBrief.model_validate(e) for e in evidence],
            notes=[],
        )


async def _get_case(s, case_id: int) -> Case:
    case = await s.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    return case


async def _detail(s, case: Case) -> CaseDetailOut:
    evidence = (
        await s.scalars(
            select(EvidenceObject)
            .join(CaseEvidence, CaseEvidence.evidence_id == EvidenceObject.id)
            .where(CaseEvidence.case_id == case.id)
            .order_by(EvidenceObject.score.desc())
        )
    ).all()
    notes = (
        await s.scalars(
            select(CaseNote).where(CaseNote.case_id == case.id).order_by(CaseNote.created_at)
        )
    ).all()
    user_ids = {n.author_user_id for n in notes if n.author_user_id}
    if case.assignee_user_id:
        user_ids.add(case.assignee_user_id)
    emails = await _user_emails(s, user_ids)
    return CaseDetailOut(
        **_case_out(case, emails.get(case.assignee_user_id), len(evidence)).model_dump(),
        description=case.description,
        evidence=[EvidenceBrief.model_validate(e) for e in evidence],
        notes=[
            NoteOut(
                id=n.id,
                author_email=emails.get(n.author_user_id),
                body=n.body,
                created_at=n.created_at,
            )
            for n in notes
        ],
    )


@router.get("/{case_id}", response_model=CaseDetailOut)
async def get_case(
    case_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CaseDetailOut:
    async with tenant_session(current.tenant_id) as s:
        case = await _get_case(s, case_id)
        return await _detail(s, case)


@router.patch("/{case_id}", response_model=CaseDetailOut)
async def update_case(
    case_id: int,
    body: CaseUpdateIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CaseDetailOut:
    async with tenant_session(current.tenant_id) as s:
        case = await _get_case(s, case_id)
        for field in ("title", "description", "severity", "status"):
            value = getattr(body, field)
            if value is not None:
                setattr(case, field, value)
        case.updated_at = datetime.now(UTC)
        await s.flush()
        return await _detail(s, case)


@router.post("/{case_id}/evidence", response_model=CaseDetailOut)
async def attach_evidence(
    case_id: int,
    body: AttachEvidenceIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CaseDetailOut:
    async with tenant_session(current.tenant_id) as s:
        case = await _get_case(s, case_id)
        if await s.get(EvidenceObject, body.evidence_id) is None:
            raise HTTPException(404, "Evidence object not found")
        existing = await s.get(CaseEvidence, (case_id, body.evidence_id))
        if existing is None:
            s.add(
                CaseEvidence(
                    case_id=case_id, evidence_id=body.evidence_id, tenant_id=current.tenant_id
                )
            )
            case.updated_at = datetime.now(UTC)
            await s.flush()
        return await _detail(s, case)


@router.post("/{case_id}/notes", response_model=CaseDetailOut, status_code=201)
async def add_note(
    case_id: int,
    body: NoteIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CaseDetailOut:
    async with tenant_session(current.tenant_id) as s:
        case = await _get_case(s, case_id)
        s.add(
            CaseNote(
                tenant_id=current.tenant_id,
                case_id=case_id,
                author_user_id=current.user_id,
                body=body.body,
            )
        )
        case.updated_at = datetime.now(UTC)
        await s.flush()
        return await _detail(s, case)
