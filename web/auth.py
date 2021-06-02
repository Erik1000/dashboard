import binascii
import uuid
from datetime import datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.security import APIKeyCookie
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from jwt import exceptions
from pydantic import EmailStr, SecretStr

from . import config, main
from .db.schema import User, WebAuthnEntry

# the api router which will be later registered in the main file
router = APIRouter()

# the cookie used to store the session token
cookie_sec = APIKeyCookie(name="session")

# Used to store the state while doing webauthn
webauthn_state = APIKeyCookie(name="_state", auto_error=True)

# argon2 password hasher and verifier
ph = PasswordHasher()

# webauthn
rp = PublicKeyCredentialRpEntity(config.WEBAUTHN_RP_ID, config.WEBAUTHN_RP_NAME)
fido2server = Fido2Server(rp)


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
                    {
                        "sub": str(user.user_uuid),
                        "exp": datetime.utcnow() + timedelta(weeks=1),
                    },
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
            session, config.SESSION_SECRET.get_secret_value(), algorithms=["HS256"]
        )

        # return the UUID in the 'sub' field
        return payload["sub"]
    except exceptions.PyJWTError:
        # If the session token is invalid in any way, raise an HTTPException handled by
        # fastapi
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid session!"
        )


# if the user is authenticated, render a settings page.
@router.get("/settings", response_class=HTMLResponse)
async def view_settings_page(
    request: Request, user_uuid: uuid.UUID = Depends(get_current_user)
):
    return main.templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            # get a list of all security keys associated with the current user and give
            # them to the template for rendering
            "security_keys": await WebAuthnEntry.query.where(
                WebAuthnEntry.user_uuid == user_uuid
            ).gino.all(),
        },
    )


# change the password of the user account.
@router.post("/change_password", response_class=HTMLResponse)
async def change_password(
    request: Request,
    user_uuid: uuid.UUID = Depends(get_current_user),
    password: SecretStr = Form(...),
    new_password: SecretStr = Form(...),
    new_password_confirm: SecretStr = Form(...),
):
    # check if the two new password fields are equal
    if new_password == new_password_confirm:
        try:
            # get the current (old) user from the database
            if user := await User.get(user_uuid):
                # verify the the provided password`s hash matches the old in the
                # database or else raise an error
                ph.verify(user.user_password_hash, password.get_secret_value())

                # update the password hash to the new password in the database
                await user.update(
                    user_password_hash=ph.hash(new_password.get_secret_value())
                ).apply()

                # render the response page
                return main.templates.TemplateResponse(
                    "settings_updated.html", {"request": request, "setting": "password"}
                )
            else:
                # Since ``get_current_user`` only checks if session keys signature is
                # correct, it is possible that a user does not exist in the database.
                # Usually this shouldn't be the case. It can happen if you sign keys
                # outside of the application or a user is deleted but the session keys
                # are still valid.
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


@router.post("/logout")
async def logout(request: Request, _=Depends(get_current_user)):
    response = main.templates.TemplateResponse("logged_out.html", {"request": request})
    response.delete_cookie("session")
    return response


# See https://webauthn.guide/#registration
# At the beginning the client requests it's credential options from the server.
# This example uses the Webauthn part of the ``fido2`` library. This library has no good
# documentation (only a bit in the source code) but it's the best library out.
# It uses cbor encoding which is a bit challenging however.
@router.post("/webauthn/add/begin", response_class=HTMLResponse)
async def begin_webauthn(
    user_uuid: uuid.UUID = Depends(get_current_user),
):
    # get the current user from the database
    user: User = await User.get(user_uuid)
    assert user, "User not found!"

    # calls the library which provides the credential options and a state
    registration_data, state = fido2server.register_begin(
        {
            # id is a byte sequence as described in
            # https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
            "id": str(user.user_uuid).encode("utf-8"),
            # we use the email address here for passwordless login later
            "name": user.user_email,
            # we don't have any 'real' name to display and therefore this example uses
            # the part before the @ in the email address.
            "displayName": user.user_email.split("@")[0],
        },
        # A list of already registered credentials is passed to the library and to the
        # client to avoid adding the same webauthn credential twice.
        User.get_webauthn_credentials(user.webauthn_credentials),
        # We want to use some kind of cross platform authenticator like a Yubikey not
        # something like Windows Hello on PCs or TouchID on some macs.
        authenticator_attachment="cross-platform",
        # We want to require the pin of the authenticator as a second factor.
        user_verification="required",
        # We want to store a credential on the client side
        resident_key=True,
    )

    # create a custom response with the ``Content-Type`` ``application/cbor``. Most
    # browsers and applications won't be able to display the body of the requests.
    response = Response(
        content=cbor.encode(registration_data), media_type="application/cbor"
    )
    state.update({"exp": datetime.utcnow() + timedelta(minutes=5)})
    # set the state parameter as a signed cookie
    response.set_cookie(
        "_state",
        jwt.encode(state, config.SESSION_SECRET.get_secret_value(), algorithm="HS256"),
    )

    # return the response.
    return response


# after the client processed the options and talked to the authenticator, it makes a
# second post request to the server to complete the action.
@router.post("/webauthn/add/complete", response_class=Response)
async def complete_webauthn(
    request: Request,
    user_uuid: uuid.UUID = Depends(get_current_user),
    # the previous state parameter as a cookie
    _state=Depends(webauthn_state),
    # The key should have a nickname so it can be easier identified.
    # E.g. ``Yubikey Keychain``.
    security_key_nickname: str = Query(...),
):
    try:
        # decode the requests body using cbor
        data = cbor.decode(await request.body())
        client_data = ClientData(data["clientDataJSON"])
        att_obj = AttestationObject(data["attestationObject"])
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to parse request body!",
        )
    try:
        # parse the state parameter
        state = jwt.decode(
            _state, config.SESSION_SECRET.get_secret_value(), algorithms=["HS256"]
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Warning: Invalid state parameter!",
        )
    try:
        # verify authentication data
        auth_data: AuthenticatorData = fido2server.register_complete(
            state,
            client_data,
            att_obj,
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication data!",
        )

    # create the response with ``Content-Type`` ``application/cbor``.
    response = Response(
        content=cbor.encode({"status": "OK"}), media_type="application/cbor"
    )

    # Tell the client to delete the cookie used to store the state since it is not
    # needed anymore.
    response.delete_cookie("_state")

    # get the current user from the database
    user = await User.get(user_uuid)

    # Guess there should be some kind of mutable array for this tho
    # SQLAlchemy somehow has trouble with mutable arrays. Because of this we simply
    # replace the whole array with the current array and add the new credential to the
    # list before sending it to the database. It needs more traffic and is slower so
    # tell me if you have a better solution.
    await user.update(
        webauthn_credentials=user.webauthn_credentials
        # we store the credential data as binary data in the database so we have to make
        # it an bytearray.
        + [bytearray(auth_data.credential_data)]
    ).apply()

    # to safe the nickname we store the credential id in the database with the
    # associated user uuid.
    await WebAuthnEntry.create(
        credential_id=auth_data.credential_data.credential_id,
        nickname=security_key_nickname,
        user_uuid=user_uuid,
    )

    # return the response
    return response


# the client performs a normal post request to remove the credential from the account.
# This will not remove the credential from the authenticator device.
@router.post("/webauthn/remove", response_class=HTMLResponse)
async def remove_security_key(
    request: Request,
    # the credential id encoded as hex string
    security_key: str = Form(...),
    user_uuid: uuid.UUID = Depends(get_current_user),
):
    # get the current user from the database
    user = await User.get(user_uuid)

    try:
        # try to make the hex string back to binary
        credential_id = binascii.unhexlify(security_key)

        credential = None

        # loop though the credentials of the user
        for c in user.get_webauthn_credentials(user.webauthn_credentials):
            # check if the credential id equals the provided credential id.
            if c.credential_id == credential_id:
                # if the credential ids match, break we are done.
                credential = c
                break

        # check if a credential were found
        if credential is not None:
            # remove the credential from the list
            user.webauthn_credentials.remove(credential)
            # send the updated list to the database.
            await user.update(webauthn_credentials=user.webauthn_credentials).apply()

            # get the authenticator from the database
            key = await WebAuthnEntry.get(credential_id)
            if key:
                # if the key is in the database, delete it.
                await key.delete()

            # return the response
            return main.templates.TemplateResponse(
                "security_key_removed.html",
                {
                    "request": request,
                    "nickname": key.nickname,
                    # make the binary credential back to a hex string.
                    "id": binascii.b2a_hex(key.credential_id).decode(),
                },
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Security key not found.",
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to parse credential id.",
        )


# render the page which will then execute the javascript
@router.get("/webauthn/auth/begin", response_class=HTMLResponse)
async def render_passwordless_login(request: Request):
    return main.templates.TemplateResponse(
        "passwordless_login.html", {"request": request}
    )


# begin passwordless authentication
@router.post("/webauthn/auth/begin", response_class=Response)
async def begin_authentication():
    # let the fido2 library generate the things for us
    auth_data, state = fido2server.authenticate_begin(user_verification="required")
    state.update({"exp": datetime.utcnow() + timedelta(minutes=5)})

    # create the response
    response = Response(content=cbor.encode(auth_data), media_type="application/cbor")

    # set the state parameter as a signed cookie
    response.set_cookie(
        "_state",
        jwt.encode(state, config.SESSION_SECRET.get_secret_value(), algorithm="HS256"),
    )

    return response


# confirm the assertion and get the current user
@router.post("/webauthn/auth/complete")
async def complete_authentication(request: Request, _state=Depends(webauthn_state)):
    try:
        # decode the request's body
        data = cbor.decode(await request.body())
        credential_id = data["credentialId"]
        client_data = ClientData(data["clientDataJSON"])
        auth_data = AuthenticatorData(data["authenticatorData"])
        signature = data["signature"]

        # the user uuid saved on the authenticator device
        user_uuid = uuid.UUID(data["userHandle"].decode("utf-8"))

        # try to get the user from the database
        user: User = await User.get(user_uuid)

        # if the user is not in the database, he does not exist.
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User does not exist!",
            )
        try:
            # parse the state parameter and verify signature
            state = jwt.decode(
                _state,
                config.SESSION_SECRET.get_secret_value(),
                algorithms=["HS256"],
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Warning: Invalid state parameter!",
            )
        else:
            # give the parameters to the fido2 library to verify them
            fido2server.authenticate_complete(
                state,
                # get the registered credentials of the user
                User.get_webauthn_credentials(user.webauthn_credentials),
                credential_id,
                client_data,
                auth_data,
                signature,
            )
            # create a session token. Sessions are only validated by their signature
            token = jwt.encode(
                {
                    "sub": str(user.user_uuid),
                    "exp": datetime.utcnow() + timedelta(weeks=1),
                },
                key=config.SESSION_SECRET.get_secret_value(),
                algorithm="HS256",
            )
            response = Response(
                content=cbor.encode({"status": "OK"}),
                media_type="application/cbor",
            )
            # set the session token
            response.set_cookie("session", token)
            # remove the state parameter because it's not longer needed
            response.delete_cookie("_state")
            return response
    except (ValueError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Received invalid data!",
        )
