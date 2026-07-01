from fastapi import APIRouter
from models import TaskRequest
from services.task_service import TaskService

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/agents/agent-analyst/tasks")
def execute_analyst_task(request: TaskRequest):
    return TaskService.execute(request)

@router.get("/")
def root():
    return {
        "message": "Agent Analyst API is running."
    }
