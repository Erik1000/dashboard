from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.config import Config

from . import auth
from .auth import get_current_user
from .db import connection

config = Config(".env")

app = FastAPI(title="Dashboard", description="This is an example app.", version="0.0.1")
templates = Jinja2Templates(directory="web/templates")
app.include_router(auth.router, prefix="/auth")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, uuid=Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {"request": request, "uuid": uuid})


@app.on_event("startup")
async def startup():
    await connection.init_connection()


@app.on_event("shutdown")
async def shutdown():
    await connection.close_connection()
