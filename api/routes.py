from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, HttpUrl  # <--- Added BaseModel import
import logging

from core.models import (
    TargetAsset,          # <--- Added TargetAsset import
    VulnerabilityRecord, 
    TaskItem, 
    AttackPath, 
    RemediationPlan, 
    AgentType, 
    VulnStatus
)
from core.database import DatabaseClient

logger = logging.getLogger("API")
router = APIRouter(prefix="/api/v1")

# --- Dependency Injection ---
def get_db(request: Request):
    return request.app.state.db

# --- Request Schemas ---

class TargetCreateRequest(BaseModel):
    domain_or_ip: str
    layer: str = "Web"
    is_authorized: bool  # Explicit human verification check
    is_crown_jewel: bool = False
    include_simulated_crown_jewel: bool = False


# --- 1. Dynamic Ingestion: Add Target Asset ---

@router.post("/targets", response_model=Dict[str, str])
async def create_target_and_start_scan(req: TargetCreateRequest, db: DatabaseClient = Depends(get_db)):
    """Dynamically ingests a new target website and kicks off the VAPT agent."""
    if not req.is_authorized:
        raise HTTPException(
            status_code=403, 
            detail="Active testing requires explicit authorization confirmation."
        )

    # 1. Store Target Asset
    metadata = {"is_crown_jewel": True} if req.is_crown_jewel else {}
    asset = TargetAsset(
        asset_identifier=req.domain_or_ip,
        layer=req.layer,
        is_authorized=req.is_authorized,
        metadata=metadata
    )
    asset_id = await db.insert_asset(asset)

    # Initialize / Update Scan Session for real-time stopwatch & status
    from datetime import datetime, timezone
    db.scan_session = {
        "is_active": True,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "target": req.domain_or_ip
    }

    # Optionally seed simulated internal crown jewel if requested and none exists
    if req.include_simulated_crown_jewel and not req.is_crown_jewel:
        existing_jewel = next((a for a in db.assets.values() if a.metadata.get("is_crown_jewel")), None)
        if not existing_jewel:
            crown_jewel = TargetAsset(
                asset_identifier="10.0.0.54 (Internal DB & Vault)",
                layer="Network",
                is_authorized=True,
                metadata={"is_crown_jewel": True}
            )
            await db.insert_asset(crown_jewel)

    # 2. Trigger VAPT Scan Task
    task = TaskItem(
        target_agent=AgentType.VAPT,
        priority=30,  # Initial recon priority
        payload={"asset_id": asset_id}
    )
    task_id = await db.insert_task(task)

    # 3. Trigger Threat Intel Task for domain assets
    if req.layer in ["Web", "Cloud"] or any(c.isalpha() for c in req.domain_or_ip):
        await db.insert_task(
            TaskItem(
                target_agent=AgentType.THREAT_INTEL,
                priority=25,
                payload={"asset_id": asset_id}
            )
        )

    return {
        "message": f"Scan initiated for {req.domain_or_ip}", 
        "asset_id": asset_id, 
        "task_id": task_id
    }


# --- 2. Dashboard: Monitored Assets ---

@router.get("/assets", response_model=List[TargetAsset])
@router.get("/targets", response_model=List[TargetAsset])
async def get_assets(db: DatabaseClient = Depends(get_db)):
    """Fetches all registered target assets."""
    return await db.get_all_assets()


# --- 3. Dashboard: Vulnerability Posture ---

@router.get("/vulnerabilities", response_model=List[VulnerabilityRecord])
async def get_vulnerabilities(status: Optional[VulnStatus] = None, db: DatabaseClient = Depends(get_db)):
    """Fetches all findings. Optionally filter by status (e.g., validated)."""
    return await db.get_vulnerabilities(status=status)


# --- 3. Dashboard: Live Priority Queue (Tasks) ---

@router.get("/queue", response_model=List[TaskItem])
async def get_task_queue(db: DatabaseClient = Depends(get_db)):
    """Fetches the Orchestrator's active and pending tasks, sorted by priority."""
    tasks = list(db.tasks.values())
    active_tasks = [t for t in tasks if t.status in ["pending", "in_progress"]]
    active_tasks.sort(key=lambda x: x.priority, reverse=True)
    return active_tasks


# --- 4. Dashboard: Attack Path Visualizer ---

@router.get("/attack-paths", response_model=List[AttackPath])
async def get_attack_paths(db: DatabaseClient = Depends(get_db)):
    """Fetches the graph nodes and edges for the frontend UI."""
    return list(db.attack_paths.values())


# --- 5. Dashboard: Remediation Studio ---

@router.get("/remediations/{vuln_id}", response_model=RemediationPlan)
async def get_remediation_plan(vuln_id: str, db: DatabaseClient = Depends(get_db)):
    """Fetches the AI-generated code patch for a specific vulnerability."""
    plan = next((p for p in db.remediations.values() if p.vulnerability_id == vuln_id), None)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found or not yet generated.")
    return plan


# --- 6. Developer Action: Trigger Retest ---

@router.post("/retest/{vuln_id}")
async def trigger_retest(vuln_id: str, db: DatabaseClient = Depends(get_db)):
    """Called by the Frontend when a developer clicks 'Verify Fix'."""
    vuln = await db.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
        
    if vuln.status == VulnStatus.REMEDIATED:
        raise HTTPException(status_code=400, detail="Vulnerability is already remediated.")

    logger.info(f"User requested manual retest for Vuln: {vuln_id}")
    
    task = TaskItem(
        target_agent=AgentType.RETEST,
        priority=100, 
        payload={"vulnerability_id": vuln_id}
    )
    task_id = await db.insert_task(task)
    
    return {"message": "Retest triggered successfully.", "task_id": task_id}
@router.get("/session")
async def get_scan_session(db: DatabaseClient = Depends(get_db)):
    """Fetches scan session metadata, start timestamp, and active status for the stopwatch."""
    session = dict(db.scan_session)
    tasks = list(db.tasks.values())
    active_tasks = [t for t in tasks if t.status in ["pending", "in_progress"]]
    
    # If tasks were scheduled and now none are active, mark as completed
    if session.get("is_active") and len(tasks) > 0 and len(active_tasks) == 0:
        session["is_active"] = False
        if not session.get("completed_at"):
            from datetime import datetime, timezone
            session["completed_at"] = datetime.now(timezone.utc).isoformat()
            db.scan_session["completed_at"] = session["completed_at"]
            db.scan_session["is_active"] = False
            
    session["active_tasks_count"] = len(active_tasks)
    session["total_tasks_count"] = len(tasks)
    return session

@router.post("/reset")
async def reset_session(db: DatabaseClient = Depends(get_db)):
    """Resets all assessment findings and tasks to return to standby."""
    await db.clear_all()
    return {"status": "success", "message": "Session reset successfully. Engine returned to standby."}

@router.get("/debug")
async def get_debug_state(db: DatabaseClient = Depends(get_db)):
    """Inspects the raw internal database state to see where tasks are stuck."""
    return {
        "assets_count": len(db.assets),
        "vulnerabilities_count": len(db.vulnerabilities),
        "tasks_count": len(db.tasks),
        "all_tasks": list(db.tasks.values()),
        "all_vulnerabilities": list(db.vulnerabilities.values())
    }

# --- 7. Model Selection & Fallback Management ---

class ModelSwitchRequest(BaseModel):
    model: str

@router.get("/models")
async def get_models_status(request: Request):
    """Returns active model, available fallback chain, and quota state."""
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator and hasattr(orchestrator, "llm_client") and hasattr(orchestrator.llm_client, "get_model_status"):
        return orchestrator.llm_client.get_model_status()
    from core.config import settings
    return {
        "current_model": settings.LLM_MODEL,
        "fallback_models": settings.LLM_FALLBACK_MODELS,
        "is_quota_exhausted": False
    }

@router.post("/models/switch")
async def switch_active_model(req: ModelSwitchRequest, request: Request):
    """Dynamically switches active model mid-session without restarting."""
    from core.config import settings
    orchestrator = getattr(request.app.state, "orchestrator", None)
    settings.LLM_MODEL = req.model
    if orchestrator and hasattr(orchestrator, "llm_client") and hasattr(orchestrator.llm_client, "switch_model"):
        orchestrator.llm_client.switch_model(req.model)
    return {
        "message": f"Successfully switched active model to {req.model}",
        "active_model": req.model
    }

# --- 8. On-Demand Vulnerability Scanners (SAST & Web) ---

class SASTScanRequest(BaseModel):
    target: str  # Code snippet or file path
    language: Optional[str] = None

class WebScanRequest(BaseModel):
    url: str
    check_injection: bool = True

@router.post("/scanners/sast")
async def run_sast_scan(req: SASTScanRequest):
    """Executes on-demand Static Application Security Testing for SQLi, XSS, and OWASP Top 10."""
    from tools.scanners import scan_code_sast
    findings = await scan_code_sast(req.target)
    return {
        "target": req.target[:80] + "..." if len(req.target) > 80 else req.target,
        "findings_count": len(findings),
        "findings": findings
    }

@router.post("/scanners/web")
async def run_web_scan(req: WebScanRequest):
    """Executes on-demand web audit for SQLi, XSS, headers, and CORS."""
    from tools.scanners import scan_web_vulnerabilities
    findings = await scan_web_vulnerabilities(req.url)
    return {
        "url": req.url,
        "findings_count": len(findings),
        "findings": findings
    }


class SQLiScanRequest(BaseModel):
    url: str
    enable_time_based: bool = True


@router.post("/scanners/sqli")
async def run_sqli_scan(req: SQLiScanRequest):
    """On-demand active SQL Injection audit (error-based, boolean-blind, time-based)."""
    from tools.vuln_scanner_mcp import tool_scan_sqli_live
    result = await tool_scan_sqli_live(req.url, enable_time_based=req.enable_time_based)
    return {
        "url": req.url,
        "vulnerability_detected": result.get("vulnerability_detected", False),
        "findings_count": result.get("count", 0),
        "techniques": result.get("techniques", []),
        "findings": result.get("findings", []),
    }

# --- 9. Assessment Report Generation & Export ---

@router.get("/report/json")
async def export_report_json(db: DatabaseClient = Depends(get_db)):
    """Downloads structured assessment summary as JSON."""
    from report.report import generate_json_report
    snapshot = await db.get_snapshot() if hasattr(db, "get_snapshot") else {
        "scan_session": getattr(db, "scan_session", {}),
        "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in db.assets.values()],
        "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in db.vulnerabilities.values()],
        "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in db.attack_paths.values()],
        "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in db.remediations.values()],
        "retests": getattr(db, "retests", {})
    }
    return generate_json_report(snapshot)

@router.get("/report/pdf")
async def export_report_pdf(db: DatabaseClient = Depends(get_db)):
    """Downloads formatted, publication-grade executive and technical PDF report."""
    from report.report import generate_pdf_report
    from fastapi.responses import Response
    snapshot = await db.get_snapshot() if hasattr(db, "get_snapshot") else {
        "scan_session": getattr(db, "scan_session", {}),
        "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in db.assets.values()],
        "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in db.vulnerabilities.values()],
        "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in db.attack_paths.values()],
        "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in db.remediations.values()],
        "retests": getattr(db, "retests", {})
    }
    pdf_bytes = generate_pdf_report(snapshot)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Security_Assessment_Report.pdf"'
        }
    )