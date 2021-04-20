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

# the cookie used to store the session token
cookie_sec = APIKeyCookie(name="session")

ph = PasswordHasher()


# on get render the html page
@router.get("/login", response_class=HTMLResponse)
async def view_login_page(request: Request):
    return main.templates.TemplateResponse("login_form.html", {"request": request})


# on post try to log the user in
@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request, email: EmailStr = Form(...), password: SecretStr = Form(...)
):
    successful = False
    reason = None
    token = None

    # search for a user model in the database. If there's no, return None
    if (
        user := await User.query.where(User.user_email == email.lower()).gino.first()
    ) is not None:

        # verify the password hash from the database against the password in the request
        try:
            if ph.verify(user.user_password_hash, password.get_secret_value()):
                # set to True since the password is correct
                successful = True

                # check if the password needs a rehash (e.g. because stronger hashing
                # options are used)
                # This is only possible on login because the client sends the password.
                if ph.check_needs_rehash(user.user_password_hash):
                    # update the new password hash in the database
                    await user.update(
                        user_password_hash=ph.hash(password.get_secret_value())
                    )

                # create a session token. Sessions are only validated by their signature
                token = jwt.encode(
                    {"sub": str(user.user_uuid)},
                    key=config.SESSION_SECRET.get_secret_value(),
                    algorithm="HS256",
                )
        except VerifyMismatchError:
            # the password hashes don't match -> wrong password
            successful = False
            reason = "Wrong password."
    else:
        # the user is not in the database and therefore doesn't exist -> unknown
        successful = False
        reason = "Unknown email."

    # render the response page. Look at the template file to see what is displayed when
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
        # at the end append the session token to the respond as cookie
        response.set_cookie("session", token)

    # return the rendered response
    return response


# on get render the register form
@router.get("/register", response_class=HTMLResponse)
async def view_registration_page(request: Request):
    return main.templates.TemplateResponse("register_form.html", {"request": request})


# register a new user with their email address and password
@router.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    email: EmailStr = Form(...),
    password: SecretStr = Form(...),
    password_confirm: SecretStr = Form(...),
):
    successful = False
    reason = None

    # check if the two passwords are the same
    if password == password_confirm:
        # check if the user already exists in the database
        if (
            await User.query.where(User.user_email == email.lower()).gino.first()
            is not None
        ):
            # if so set the corresponding reason
            reason = "Already registered."
        else:
            # if the user is not already in the database, insert their
            await User.create(
                user_uuid=uuid.uuid4(),
                user_email=email.lower(),
                user_password_hash=ph.hash(password.get_secret_value()),
            )
            # set successful to True after the insert was successful
            successful = True
    else:
        # The passwords are not the same. Set the corresponding reason.
        reason = "Passwords not equal."

    # render the response template. See the template file to know what is displayed when
    return main.templates.TemplateResponse(
        "register_response.html",
        {
            "request": request,
            "reason": reason,
            "successful": successful,
            "email": email.lower(),
        },
    )


# Function used with Depends on sites that require authentication.
# returns the UUID of the user.
async def get_current_user(session: str = Depends(cookie_sec)) -> uuid.UUID:
    try:
        # try to decode the session token and check the signature
        payload = jwt.decode(
            session, config.SESSION_SECRET.get_secret_value(), algorithms="HS256"
        )

        # return the UUID in the 'sub' field
        return payload["sub"]
    except exceptions.PyJWTError:
        # If the session token is invalid in any way, raise an HTTPException handled by
        # fastapi
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session!"
        )


@router.get("/settings")
async def view_settings_page(request: Request, _=Depends(get_current_user)):
    return main.templates.TemplateResponse("settings.html", {"request": request})


@router.post("/change_password")
async def change_password(
    request: Request,
    user_uuid: uuid.UUID = Depends(get_current_user),
    password: SecretStr = Form(...),
    new_password: SecretStr = Form(...),
    new_password_confirm: SecretStr = Form(...),
):
    if new_password == new_password_confirm:
        try:
            if user := await User.get(user_uuid):
                ph.verify(user.user_password_hash, password.get_secret_value())
                await user.update(
                    user_password_hash=ph.hash(new_password.get_secret_value())
                ).apply()
                return main.templates.TemplateResponse(
                    "settings_updated.html", {"request": request, "setting": "password"}
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found. That's strange and shouldn't be the case.",
                )
        except VerifyMismatchError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password."
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="New passwords don't match!",
        )
