from flask import abort
from sqlalchemy import orm as so
from sqlalchemy.exc import IntegrityError

from bueno.app import db


class CRUDMixin:
    __table_args__ = {"extend_existing": True}

    id: so.Mapped[int] = so.mapped_column(primary_key=True)

    @classmethod
    def read(cls, id) -> object or None:
        if any(
            (
                isinstance(id, (str, bytes)) and id.isdigit(),
                isinstance(id, (int, float)),
            )
        ):
            return db.session.get(cls, int(id)) or abort(404)

    def _save(self, commit=True):
        db.session.add(self)
        if commit:
            try:
                db.session.commit()
            except IntegrityError:
                abort(409)
        return self

    def update(self, commit=True, **kwargs):
        for attr, value in kwargs.items():
            setattr(self, attr, value)

        return commit and self._save() or self

    def create(self, commit=True):
        return commit and self._save() or self

    save = create

    def delete(self, commit=True):
        db.session.delete(self)
        return commit and db.session.commit()
