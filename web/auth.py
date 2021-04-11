import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyCookie
from jwt import exceptions
from pydantic import EmailStr, SecretStr

from . import config, main
from .db.schema import User

router = APIRouter()
cookie_sec = APIKeyCookie(name="session")

ph = PasswordHasher()


@router.get("/login", response_class=HTMLResponse)
async def view_login_page(request: Request):
    return main.templates.TemplateResponse("login_form.html", {"request": request})


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request, email: EmailStr = Form(...), password: SecretStr = Form(...)
):
    successful = False
    reason = None
    token = None
    if (
        user := await User.query.where(User.user_email == email.lower()).gino.first()
    ) is not None:
        try:
            if ph.verify(user.user_password_hash, password.get_secret_value()):
                successful = True
                if ph.check_needs_rehash(user.user_password_hash):
                    await user.update(
                        user_password_hash=ph.hash(password.get_secret_value())
                    )
                token = jwt.encode(
                    {"sub": str(user.user_uuid)},
                    key=config.SESSION_SECRET.get_secret_value(),
                    algorithm="HS256",
                )
        except VerifyMismatchError:
            successful = False
            reason = "Wrong password."
    else:
        successful = False
        reason = "Unknown email."

    response = main.templates.TemplateResponse(
        "login_response.html",
        {
            "request": request,
            "reason": reason,
            "email": email.lower(),
            "successful": successful,
        },
    )
    if token is not None:
        response.set_cookie("session", token)
    return response


@router.get("/register", response_class=HTMLResponse)
async def view_registration_page(request: Request):
    return main.templates.TemplateResponse("register_form.html", {"request": request})


@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    email: EmailStr = Form(...),
    password: SecretStr = Form(...),
    password_confirm: SecretStr = Form(...),
):
    successful = False
    reason = None
    if password == password_confirm:
        if (
            await User.query.where(User.user_email == email.lower()).gino.first()
            is not None
        ):
            reason = "Already registered."
        else:
            await User.create(
                user_uuid=uuid.uuid4(),
                user_email=email.lower(),
                user_password_hash=ph.hash(password.get_secret_value()),
            )
            successful = True
    else:
        reason = "Passwords not equal."

    return main.templates.TemplateResponse(
        "register_response.html",
        {
            "request": request,
            "reason": reason,
            "successful": successful,
            "email": email.lower(),
        },
    )


async def get_current_user(session: str = Depends(cookie_sec)) -> uuid.UUID:
    try:
        payload = jwt.decode(
            session, config.SESSION_SECRET.get_secret_value(), algorithms="HS256"
        )
        return payload["sub"]
    except exceptions.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session!"
        )
