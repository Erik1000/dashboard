from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.config import Config
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth
from .auth import get_current_user
from .db import connection

config = Config(".env")

app = FastAPI(title="Dashboard", description="This is an example app.", version="0.0.1")
templates = Jinja2Templates(directory="web/templates")
app.include_router(auth.router, prefix="/auth")
app.mount("/static", StaticFiles(directory="web/static"), name="static")


# render some example page if authenticated
@app.get("/", response_class=HTMLResponse)
async def root(request: Request, uuid=Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {"request": request, "uuid": uuid})


@app.on_event("startup")
async def startup():
    # connect to the database
    await connection.init_connection()


@app.on_event("shutdown")
async def shutdown():
    # disconnect from the database
    await connection.close_connection()


# add custom exception handler for HTTPException so it doesn't respond with json.
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, e: StarletteHTTPException):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": e.status_code, "detail": e.detail},
        status_code=e.status_code,
    )
