"""DB-only persistence for sanitized mailbox intake proposals."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import EmailLinkProposal


class EmailLinkProposalRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_for_receipt(self, receipt_id: str) -> list[EmailLinkProposal]:
        return list(
            self._session.scalars(
                select(EmailLinkProposal)
                .where(EmailLinkProposal.receipt_id == receipt_id)
                .order_by(EmailLinkProposal.created_at, EmailLinkProposal.id)
            )
        )

    def add(self, **values: object) -> EmailLinkProposal:
        row = EmailLinkProposal(**values)
        self._session.add(row)
        self._session.flush()
        return row
