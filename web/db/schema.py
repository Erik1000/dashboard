from binascii import b2a_hex
from uuid import UUID

from fido2.ctap2 import AttestedCredentialData
from pydantic import EmailStr, StrictStr
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as UUID_TYPE
from sqlalchemy.types import LargeBinary

from .connection import DATABASE as DB


class User(DB.Model):
    # TODO: add index search for email
    __tablename__ = "dashboard_users"
    user_uuid: UUID = DB.Column(UUID_TYPE(), primary_key=True)
    user_email: EmailStr = DB.Column(DB.String(), unique=True, nullable=False)
    user_password_hash: StrictStr = DB.Column(DB.String, unique=True, nullable=False)
    webauthn_credentials: [bytes] = DB.Column(
        ARRAY(LargeBinary), default=[], nullable=False
    )

    @staticmethod
    def get_webauthn_credentials(cs) -> []:
        r = []
        assert cs is not None, "User credentials should be empty not None"
        for c in cs:
            r.append(AttestedCredentialData(c))
        return r


class WebAuthnEntry(DB.Model):
    __tablename__ = "webauthn_entries"
    credential_id: bytes = DB.Column(LargeBinary, primary_key=True)
    nickname: str = DB.Column(DB.Unicode(), default="Unknown Key")
    user_uuid: UUID = DB.Column(
        UUID_TYPE(), ForeignKey("dashboard_users.user_uuid"), nullable=False
    )

    @staticmethod
    def as_hex(bs):
        return b2a_hex(bs).decode()
