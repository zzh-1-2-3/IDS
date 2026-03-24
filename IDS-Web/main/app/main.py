from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import os

from app.core.database import engine, Base, SessionLocal
from app.api import api_router
from app.core.config import settings
from app.services.model_service import ModelService

# 创建数据库表
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时执行
    db = SessionLocal()
    try:
        ModelService.reset_all_model_status(db)
        ModelService.initialize_models_from_directory(db)
    finally:
        db.close()
    yield
    # 关闭时执行（如果需要）

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="基于深度学习的入侵检测系统Web端",
    lifespan=lifespan
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# 挂载评估结果图片目录
base_dir = os.path.dirname(os.path.dirname(__file__))
eval_dir = os.path.join(base_dir, "eval_results")
os.makedirs(eval_dir, exist_ok=True)
app.mount("/eval_results", StaticFiles(directory=eval_dir), name="eval_results")

# 挂载 Chart.js 目录
chart_dir = os.path.join(base_dir, "chart")
if os.path.exists(chart_dir):
    app.mount("/chart", StaticFiles(directory=chart_dir), name="chart")

# 注册API路由
app.include_router(api_router, prefix="/api")

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>IDS入侵检测系统</title>
        <meta charset="utf-8">
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                text-align: center;
                color: white;
            }
            h1 { font-size: 3em; margin-bottom: 20px; }
            p { font-size: 1.2em; }
            a {
                display: inline-block;
                margin-top: 30px;
                padding: 15px 30px;
                background: white;
                color: #667eea;
                text-decoration: none;
                border-radius: 30px;
                font-weight: bold;
                transition: transform 0.3s;
            }
            a:hover { transform: scale(1.05); }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>IDS入侵检测系统</h1>
            <p>基于深度学习的网络流量分析与入侵检测</p>
            <a href="/static/index.html">进入系统</a>
        </div>
    </body>
    </html>
    """

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": settings.VERSION}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
