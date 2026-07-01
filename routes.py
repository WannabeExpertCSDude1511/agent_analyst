from fastapi import APIRouter
from models import TaskRequest

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/tasks")
def create_task(request: TaskRequest):
    return {
        "status": "completed",
        "response": {
            "summary": "No tools executed.",
            "findings": []
        }
    }

@router.get("/")
def root():
    return {
        "message": "Agent Analyst API is running."
    }