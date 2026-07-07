"""Sky-Eye FastAPI 应用入口"""

from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from app.config import settings
from app.database import init_db
from app.api import router as api_router

# 模板和静态文件
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# 纯 Jinja2 环境，不用 Starlette 的 Jinja2Templates
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    auto_reload=settings.DEBUG,
)


def render_template(name: str, **context) -> str:
    """渲染模板返回 HTML 字符串"""
    t = jinja_env.get_template(name)
    return t.render(**context)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Sky-Eye 资产挖掘与打点系统",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(api_router, prefix="/api/v1")


# ── 页面路由 ──

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    html = render_template("dashboard.html", request=request)
    return HTMLResponse(html)


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    html = render_template("assets.html", request=request)
    return HTMLResponse(html)


@app.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    html = render_template("tasks.html", request=request)
    return HTMLResponse(html)


@app.get("/vulns", response_class=HTMLResponse)
async def vulns_page(request: Request):
    html = render_template("vulns.html", request=request)
    return HTMLResponse(html)
