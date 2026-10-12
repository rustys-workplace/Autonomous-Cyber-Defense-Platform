import asyncio
import json
import logging
import os
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from core.models import (
    TargetAsset, VulnerabilityRecord, TaskItem, 
    RemediationPlan, AttackPath, VulnStatus
)

logger = logging.getLogger("SharedDatabase")


def normalize_source(raw_source: str) -> str:
    """Strictly enforces source IN ('tool', 'ai_inference') per DB schema constraints."""
    s = (raw_source or "").lower()
    if any(k in s for k in ("tool", "nmap", "intel", "mcp", "scanner", "cve", "recon")):
        return "tool"
    return "ai_inference"


def normalize_status(raw_status: Any) -> str:
    """Maps domain status to relational lifecycle status ('pending', 'processing', 'done')."""
    val = raw_status.value if hasattr(raw_status, "value") else str(raw_status)
    s = val.lower().strip()
    if s in ("unvalidated", "pending"):
        return "pending"
    elif s in ("validating", "processing", "in_progress"):
        return "processing"
    elif s in ("validated", "remediated", "false_positive", "done", "completed"):
        return "done"
    return "pending"




class DatabaseClient:
    """
    Dual-mode Database Engine:
    - If DATABASE_URL is configured and PostgreSQL is reachable, operates with asyncpg connection pool.
    - Gracefully falls back to thread-safe in-memory storage if PostgreSQL is unreachable or unconfigured.
    - Guarantees seamless compatibility across Docker, CI/CD, and standalone local environments.
    """
    def __init__(self, database_url: Optional[str] = None):
        self._lock = asyncio.Lock()
        # Signalled whenever a pending task is inserted so the Orchestrator can
        # dispatch immediately instead of polling on a timer (minimizes the
        # discovery -> validation -> remediation latency).
        self._task_available = asyncio.Event()
        self.database_url = database_url or os.getenv("DATABASE_URL")
        self.pg_pool = None
        self.use_postgres = False
        
        # In-memory tables (always maintained for zero-latency queries & fallback)
        self.assets: Dict[str, TargetAsset] = {}
        self.vulnerabilities: Dict[str, VulnerabilityRecord] = {}
        self.tasks: Dict[str, TaskItem] = {}
        self.remediations: Dict[str, RemediationPlan] = {}
        self.attack_paths: Dict[str, AttackPath] = {}
        self.retests: Dict[str, Dict[str, Any]] = {}
        self.scan_session: Dict[str, Any] = {
            "is_active": False,
            "started_at": None,
            "completed_at": None,
            "target": None
        }

    async def initialize(self):
        """Initializes PostgreSQL connection pool if configured, with schema verification."""
        if not self.database_url:
            logger.info("DATABASE_URL not set; running in thread-safe in-memory database mode.")
            return

        try:
            import asyncpg
            logger.info(f"Connecting to PostgreSQL persistence layer...")
            self.pg_pool = await asyncpg.create_pool(
                dsn=self.database_url,
                min_size=1,
                max_size=10,
                timeout=5.0,
                command_timeout=10.0
            )
            
            # Apply schema if schema file exists
            schema_candidates = [
                os.path.join(os.path.dirname(__file__), "..", "db", "schema.sql"),
                os.path.join(os.getcwd(), "db", "schema.sql")
            ]
            for schema_path in schema_candidates:
                if os.path.exists(schema_path):
                    try:
                        with open(schema_path, "r", encoding="utf-8") as f:
                            schema_sql = f.read()
                        async with self.pg_pool.acquire() as conn:
                            await conn.execute(schema_sql)
                        logger.info("PostgreSQL schema successfully verified/applied.")
                        break
                    except Exception as schema_err:
                        logger.warning(f"Could not apply schema.sql: {schema_err}")

            self.use_postgres = True
            logger.info("PostgreSQL persistence layer active.")
        except Exception as e:
            logger.warning(f"PostgreSQL connection failed ({e}). Gracefully running in in-memory mode.")
            self.pg_pool = None
            self.use_postgres = False

    async def close(self):
        """Gracefully closes the connection pool."""
        if self.pg_pool:
            try:
                await self.pg_pool.close()
            except Exception as e:
                logger.warning(f"Error closing PostgreSQL pool: {e}")
            self.pg_pool = None
            self.use_postgres = False

    async def clear_all(self):
        """Clears all session data to allow running a fresh scan."""
        async with self._lock:
            self.assets.clear()
            self.vulnerabilities.clear()
            self.tasks.clear()
            self.remediations.clear()
            self.attack_paths.clear()
            self.retests.clear()
            self.scan_session = {
                "is_active": False,
                "started_at": None,
                "completed_at": None,
                "target": None
            }

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        TRUNCATE TABLE retests, remediations, attack_paths, 
                                       validated_findings, findings, assets, tasks CASCADE;
                    """)
            except Exception as e:
                logger.warning(f"Failed to truncate PostgreSQL tables: {e}")

    # --- Asset Operations ---
    
    async def insert_asset(self, asset: TargetAsset) -> str:
        async with self._lock:
            self.assets[asset.id] = asset

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO assets (id, target, asset_type, host, port, protocol, is_authorized, metadata, status)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        ON CONFLICT (id) DO UPDATE SET
                            target = EXCLUDED.target,
                            asset_type = EXCLUDED.asset_type,
                            is_authorized = EXCLUDED.is_authorized,
                            metadata = EXCLUDED.metadata,
                            status = EXCLUDED.status;
                    """, 
                        asset.id, 
                        asset.asset_identifier, 
                        asset.layer, 
                        asset.metadata.get("host", asset.asset_identifier),
                        asset.metadata.get("port"),
                        asset.metadata.get("protocol", "tcp"),
                        asset.is_authorized,
                        json.dumps(asset.metadata),
                        "pending"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_asset error: {e}")

        return asset.id

    async def get_asset(self, asset_id: str) -> Optional[TargetAsset]:
        async with self._lock:
            return self.assets.get(asset_id)

    async def get_all_assets(self) -> List[TargetAsset]:
        async with self._lock:
            return list(self.assets.values())

    # --- Vulnerability Operations ---

    async def insert_vulnerability(self, vuln: VulnerabilityRecord) -> str:
        async with self._lock:
            self.vulnerabilities[vuln.id] = vuln

        if self.use_postgres and self.pg_pool:
            try:
                clean_source = normalize_source(vuln.discovery_source)
                clean_status = normalize_status(vuln.status)
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO findings (
                            id, asset_id, title, description, severity, cve_id, 
                            source, raw_evidence, criticality_score, confidence_score, 
                            has_leaked_creds, layer, metadata, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                        ON CONFLICT (id) DO UPDATE SET
                            title = EXCLUDED.title,
                            criticality_score = EXCLUDED.criticality_score,
                            confidence_score = EXCLUDED.confidence_score,
                            has_leaked_creds = EXCLUDED.has_leaked_creds,
                            metadata = EXCLUDED.metadata,
                            status = EXCLUDED.status;
                    """,
                        vuln.id,
                        vuln.asset_id,
                        vuln.title,
                        vuln.metadata.get("description", vuln.title),
                        vuln.metadata.get("severity", "MEDIUM"),
                        vuln.metadata.get("cve_id"),
                        clean_source,
                        vuln.proof_of_concept or vuln.metadata.get("evidence", ""),
                        float(vuln.criticality_score),
                        float(vuln.confidence_score),
                        bool(vuln.has_leaked_creds),
                        vuln.layer,
                        json.dumps(vuln.metadata),
                        clean_status
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_vulnerability error: {e}")

        return vuln.id

    async def get_vulnerability(self, vuln_id: str) -> Optional[VulnerabilityRecord]:
        async with self._lock:
            return self.vulnerabilities.get(vuln_id)

    async def get_vulnerabilities(self, status: Optional[VulnStatus] = None) -> List[VulnerabilityRecord]:
        async with self._lock:
            if status:
                return [v for v in self.vulnerabilities.values() if v.status == status]
            return list(self.vulnerabilities.values())

    async def update_vulnerability(self, vuln_id: str, **kwargs):
        async with self._lock:
            if vuln_id in self.vulnerabilities:
                vuln = self.vulnerabilities[vuln_id]
                for key, value in kwargs.items():
                    if hasattr(vuln, key):
                        setattr(vuln, key, value)

        if self.use_postgres and self.pg_pool:
            try:
                vuln = self.vulnerabilities.get(vuln_id)
                if vuln:
                    clean_status = normalize_status(vuln.status)
                    async with self.pg_pool.acquire() as conn:
                        await conn.execute("""
                            UPDATE findings SET
                                criticality_score = $2,
                                confidence_score = $3,
                                raw_evidence = $4,
                                status = $5,
                                metadata = $6
                            WHERE id = $1;
                        """,
                            vuln.id,
                            float(vuln.criticality_score),
                            float(vuln.confidence_score),
                            vuln.proof_of_concept or "",
                            clean_status,
                            json.dumps(vuln.metadata)
                        )

                        # If validated, record in validated_findings
                        if vuln.status == VulnStatus.VALIDATED:
                            val_id = f"val_{vuln.id}"
                            await conn.execute("""
                                INSERT INTO validated_findings (
                                    id, finding_id, exploitable, confidence_score, 
                                    cvss_score, poc_exists, validation_evidence, mitre_technique, status
                                )
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                                ON CONFLICT (id) DO UPDATE SET
                                    exploitable = EXCLUDED.exploitable,
                                    confidence_score = EXCLUDED.confidence_score,
                                    poc_exists = EXCLUDED.poc_exists,
                                    validation_evidence = EXCLUDED.validation_evidence,
                                    status = EXCLUDED.status;
                            """,
                                val_id,
                                vuln.id,
                                True,
                                float(vuln.confidence_score),
                                float(vuln.criticality_score),
                                bool(vuln.proof_of_concept),
                                vuln.proof_of_concept or "Validated non-destructively",
                                vuln.metadata.get("mitre_technique", "T1190"),
                                "done"
                            )
            except Exception as e:
                logger.warning(f"PostgreSQL update_vulnerability error: {e}")

    async def boost_vulnerability_priority(self, vuln_id: str, multiplier: float):
        """Used by the Attack-Path agent to increase priority based on contextual risk."""
        async with self._lock:
            if vuln_id in self.vulnerabilities:
                vuln = self.vulnerabilities[vuln_id]
                new_score = min(10.0, vuln.criticality_score * multiplier)
                vuln.criticality_score = new_score
                logger.info(f"Boosted Vuln {vuln_id} score to {new_score}")
        
        await self.update_vulnerability(vuln_id, criticality_score=new_score)

    # --- Task Queue (Orchestrator) Operations ---

    async def insert_task(self, task: TaskItem) -> str:
        async with self._lock:
            self.tasks[task.id] = task
            # Wake the Orchestrator immediately if this task is dispatchable.
            if task.status == "pending":
                self._task_available.set()

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO tasks (id, target_agent, priority, payload, status)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (id) DO UPDATE SET
                            priority = EXCLUDED.priority,
                            payload = EXCLUDED.payload,
                            status = EXCLUDED.status;
                    """,
                        task.id,
                        str(task.target_agent),
                        int(task.priority),
                        json.dumps(task.payload),
                        str(task.status)
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_task error: {e}")

        return task.id

    async def get_highest_priority_task(self) -> Optional[TaskItem]:
        """Fetches the pending task with the highest priority integer."""
        async with self._lock:
            pending_tasks = [t for t in self.tasks.values() if t.status == "pending"]
            if not pending_tasks:
                return None
            pending_tasks.sort(key=lambda x: x.priority, reverse=True)
            return pending_tasks[0]

    async def wait_for_task(self, timeout: Optional[float] = None):
        """Blocks until a pending task is (or already is) available.

        Race-safe: clears the signal, re-checks for any pending task that may
        have been inserted between the caller's last fetch and this clear, and
        only then waits. The timeout is a self-healing safety net so a missed
        wakeup can never stall the pipeline permanently.
        """
        async with self._lock:
            has_pending = any(t.status == "pending" for t in self.tasks.values())
            if has_pending:
                self._task_available.set()
                return True
            self._task_available.clear()

        try:
            await asyncio.wait_for(self._task_available.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def mark_task_in_progress(self, task_id: str):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = "in_progress"

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("UPDATE tasks SET status = 'in_progress' WHERE id = $1;", task_id)
            except Exception as e:
                logger.warning(f"PostgreSQL mark_task_in_progress error: {e}")

    async def complete_task(self, task_id: str, status: str = "completed"):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = status

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("UPDATE tasks SET status = $2 WHERE id = $1;", task_id, status)
            except Exception as e:
                logger.warning(f"PostgreSQL complete_task error: {e}")

    # --- Attack Path & Remediation Operations ---

    async def save_attack_path(self, path: AttackPath) -> str:
        async with self._lock:
            self.attack_paths[path.id] = path

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO attack_paths (
                            id, path_nodes, path_edges, cumulative_risk, 
                            break_chain_target, mitre_chain, attack_narrative, 
                            simplified_flow, grouped_vectors, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        ON CONFLICT (id) DO UPDATE SET
                            path_nodes = EXCLUDED.path_nodes,
                            path_edges = EXCLUDED.path_edges,
                            cumulative_risk = EXCLUDED.cumulative_risk,
                            break_chain_target = EXCLUDED.break_chain_target,
                            mitre_chain = EXCLUDED.mitre_chain,
                            attack_narrative = EXCLUDED.attack_narrative,
                            simplified_flow = EXCLUDED.simplified_flow,
                            grouped_vectors = EXCLUDED.grouped_vectors,
                            status = EXCLUDED.status;
                    """,
                        path.id,
                        json.dumps(path.nodes),
                        json.dumps(path.edges),
                        float(path.total_risk_score),
                        path.chokepoint_vuln_id,
                        json.dumps(path.mitre_tactics),
                        path.attack_narrative,
                        json.dumps(path.simplified_flow),
                        json.dumps(path.grouped_vectors),
                        "done"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL save_attack_path error: {e}")

        return path.id

    async def clear_attack_paths(self):
        async with self._lock:
            self.attack_paths.clear()

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("TRUNCATE TABLE attack_paths CASCADE;")
            except Exception as e:
                logger.warning(f"PostgreSQL clear_attack_paths error: {e}")

    async def insert_remediation_plan(self, plan: RemediationPlan) -> str:
        async with self._lock:
            self.remediations[plan.id] = plan

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO remediations (
                            id, finding_id, root_cause, fix_suggestion, 
                            code_snippet, target_tech_stack, original_code_snippet, 
                            patch_type, priority, applied, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        ON CONFLICT (id) DO UPDATE SET
                            root_cause = EXCLUDED.root_cause,
                            fix_suggestion = EXCLUDED.fix_suggestion,
                            code_snippet = EXCLUDED.code_snippet,
                            applied = EXCLUDED.applied,
                            status = EXCLUDED.status;
                    """,
                        plan.id,
                        plan.vulnerability_id,
                        plan.root_cause_analysis,
                        f"Apply patch for {plan.vulnerability_id}",
                        plan.patched_code_snippet,
                        plan.target_tech_stack,
                        plan.original_code_snippet,
                        plan.patch_type,
                        50,
                        plan.is_applied,
                        "pending"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_remediation_plan error: {e}")

        return plan.id

    # --- Retest Operations ---

    async def record_retest(
        self, 
        finding_id: str, 
        remediation_id: Optional[str] = None, 
        still_vulnerable: bool = False, 
        evidence: str = ""
    ) -> str:
        """Records a patch verification / retest audit event in DB."""
        retest_id = str(uuid.uuid4())
        record = {
            "id": retest_id,
            "finding_id": finding_id,
            "remediation_id": remediation_id,
            "still_vulnerable": still_vulnerable,
            "evidence": evidence,
            "retested_at": datetime.now(timezone.utc).isoformat(),
            "status": "done"
        }
        async with self._lock:
            self.retests[retest_id] = record

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO retests (id, finding_id, remediation_id, still_vulnerable, evidence, status)
                        VALUES ($1, $2, $3, $4, $5, 'done');
                    """,
                        retest_id,
                        finding_id,
                        remediation_id,
                        still_vulnerable,
                        evidence
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL record_retest error: {e}")

        return retest_id

    async def get_retests(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        async with self._lock:
            records = list(self.retests.values())
            if finding_id:
                return [r for r in records if r.get("finding_id") == finding_id]
            return records

    async def get_snapshot(self) -> Dict[str, Any]:
        """Provides a complete serializable snapshot of the security assessment."""
        async with self._lock:
            return {
                "scan_session": dict(self.scan_session),
                "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in self.assets.values()],
                "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in self.vulnerabilities.values()],
                "tasks": [t.model_dump() if hasattr(t, "model_dump") else t.dict() for t in self.tasks.values()],
                "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in self.attack_paths.values()],
                "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in self.remediations.values()],
                "retests": list(self.retests.values())
            }