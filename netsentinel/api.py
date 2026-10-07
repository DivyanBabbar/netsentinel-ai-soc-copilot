"""FastAPI service. Run with: uvicorn netsentinel.api:app --reload"""
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .actions import execute_action
from .retriever import BM25Retriever, load_techniques
from .triage import LLMUnavailableError, TriageError, run_triage

KNOWLEDGE_BASE_PATH = Path(os.environ.get("KNOWLEDGE_BASE", Path(__file__).resolve().parent.parent / "knowledge_base" / "techniques.json"))
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() != "false"
PROTECTED_TARGETS = tuple(filter(None, os.environ.get("PROTECTED_TARGETS", "").split(",")))

app = FastAPI(title="NetSentinel", version="0.2.0")
retriever = BM25Retriever(load_techniques(KNOWLEDGE_BASE_PATH))


class TriageRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=20000)
    use_rag: bool = True


class ActionModel(BaseModel):
    type: str
    target: str
    reason: str = ""


class ExecuteRequest(BaseModel):
    action: ActionModel
    approved: bool = False


@app.get("/health")
def health():
    return {"status": "ok", "techniques_loaded": len(retriever.techniques), "dry_run": DRY_RUN}


@app.post("/triage")
def triage(request: TriageRequest):
    try:
        return run_triage(request.logs, retriever, use_rag=request.use_rag, protected_targets=PROTECTED_TARGETS)
    except LLMUnavailableError as error:
        raise HTTPException(status_code=503, detail=f"model unavailable: {error}")
    except TriageError as error:
        raise HTTPException(status_code=502, detail=f"model output rejected: {error}")


@app.post("/actions/execute")
def execute(request: ExecuteRequest, x_action_approval_token: str | None = Header(None)):
    if not request.approved:
        raise HTTPException(status_code=400, detail="action requires explicit human approval")
    if not DRY_RUN:
        expected_token = os.environ.get("ACTION_APPROVAL_TOKEN", "")
        if not expected_token:
            raise HTTPException(status_code=503, detail="live actions are disabled until ACTION_APPROVAL_TOKEN is configured")
        if not x_action_approval_token or not secrets.compare_digest(x_action_approval_token, expected_token):
            raise HTTPException(status_code=403, detail="valid operator approval token required for live actions")
    return execute_action(
        request.action.model_dump(),
        dry_run=DRY_RUN,
        slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
        protected_targets=PROTECTED_TARGETS,
    )
