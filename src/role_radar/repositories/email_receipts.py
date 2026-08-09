"""DB-only idempotency and terminal receipt repository."""

from typing import cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
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
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
            return row
        except IntegrityError:
            existing = self.get(
                str(values["source_id"]),
                cast(int, values["uidvalidity"]),
                cast(int, values["uid"]),
            )
            if existing is None:
                raise
            return existing
