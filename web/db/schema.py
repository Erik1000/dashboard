from uuid import UUID

from pydantic import EmailStr, StrictStr
from sqlalchemy.dialects.postgresql import UUID as UUID_TYPE

from .connection import DATABASE as DB


class User(DB.Model):
    # TODO: add index search for email
    __tablename__ = "dashboard_users"
    user_uuid: UUID = DB.Column(UUID_TYPE(), primary_key=True)
    user_email: EmailStr = DB.Column(DB.String(), unique=True, nullable=False)
    user_password_hash: StrictStr = DB.Column(DB.String, unique=True, nullable=False)
