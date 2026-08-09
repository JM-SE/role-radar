"""DB-only idempotency and terminal receipt repository."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import EmailReceipt


class EmailReceiptRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, source_id: str, uidvalidity: int, uid: int) -> EmailReceipt | None:
        return self._session.scalar(
            select(EmailReceipt).where(
                EmailReceipt.source_id == source_id,
                EmailReceipt.uidvalidity == uidvalidity,
                EmailReceipt.uid == uid,
            )
        )

    def create_terminal(self, **values: object) -> EmailReceipt:
        row = EmailReceipt(**values)
        self._session.add(row)
        self._session.flush()
        return row
