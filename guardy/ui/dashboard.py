from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Callable, Awaitable, Dict, Any, List
import os

# Locate the templates directory relative to this file
current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")
templates = Jinja2Templates(directory=templates_dir)

def get_dashboard_router(
    get_system_stats: Callable[[], Awaitable[Dict[str, Any]]],
    get_recent_alerts: Callable[[], Awaitable[List[Dict[str, Any]]]],
    get_user_logs: Callable[[str], Awaitable[List[Dict[str, Any]]]] = None,
    generate_llm_report: Callable[[str], Awaitable[str]] = None
) -> APIRouter:
    """
    Creates and returns a FastAPI APIRouter serving the web dashboard.
    It expects backend developers to pass async callback functions that fetch the real data.
    """
    router = APIRouter(prefix="/security-dashboard", tags=["Security Dashboard"])

    @router.get("/", response_class=HTMLResponse)
    async def render_dashboard(request: Request):
        # 1. Fetch data from backend logic via provided callbacks
        stats = await get_system_stats()
        alerts = await get_recent_alerts()
        
        # 2. Render Template
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "stats": stats,
            "alerts": alerts
        })

    @router.get("/user/{user_id}", response_class=HTMLResponse)
    async def render_user_detail(request: Request, user_id: str):
        logs = []
        if get_user_logs:
            logs = await get_user_logs(user_id)
            
        return templates.TemplateResponse("user_detail.html", {
            "request": request,
            "user_id": user_id,
            "logs": logs
        })
        
    @router.post("/generate-report/{user_id}")
    async def trigger_llm_report(user_id: str):
        if not generate_llm_report:
            return {"status": "error", "message": "LLM generation not configured by backend."}
        try:
            report_markdown = await generate_llm_report(user_id)
            return {"status": "success", "report": report_markdown}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    return router
