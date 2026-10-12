import asyncio
import logging
from typing import Dict, Any
from core.models import AgentType, TaskItem
from agents.vapt import VAPTAgent, MockLLMClient
from agents.validation import ValidationAgent, MockValidationLLM
from agents.attack_path import AttackPathAgent, MockAttackPathLLM
from agents.threat_intel import ThreatIntelAgent
from agents.remediation import RemediationAgent, MockRemediationLLM
from agents.retesting import RetestingAgent, MockRetestEvaluator
from tools.llm import RealLLMClient
from core.config import settings

logger = logging.getLogger("Orchestrator")


class UnifiedMockLLM(MockLLMClient, MockValidationLLM, MockAttackPathLLM, MockRemediationLLM):
    """
    Deterministic offline LLM used when no real LLM API key is configured.

    It composes every per-agent mock so that a SINGLE client exposes the full
    capability surface the real LLM client provides:
      - extract_cpe_from_nmap   (VAPT Agent)
      - generate_safe_poc       (Validation Agent)
      - evaluate_chainability / evaluate_vuln_transition (Attack-Path Agent)
      - generate_patch          (Remediation Agent)

    Without this, the fallback client only implemented extract_cpe_from_nmap,
    which crashed the Validation and Remediation agents on every task whenever
    the platform ran in its default no-API-key mode.
    """
    pass


class Orchestrator:
    def __init__(self, db_client):
        self.db = db_client
        # Map agent enums to their respective async handlers.
        if settings.has_llm:
            self.llm_client = RealLLMClient(api_key=settings.LLM_API_KEY, base_url=settings.LLM_BASE_URL, model=settings.LLM_MODEL)
        else:
            # No API key: use the fully-featured deterministic client so every
            # agent (not just VAPT) works offline / in CI / in demos.
            self.llm_client = UnifiedMockLLM()
            
        self.vapt_agent = VAPTAgent(db_client=db_client, llm_client=self.llm_client, nvd_api_key=settings.NVD_API_KEY)
        self.validation_agent = ValidationAgent(db_client, self.llm_client)
        self.attack_path_agent = AttackPathAgent(db_client, self.llm_client)
        self.threat_intel_agent = ThreatIntelAgent(db_client, config={
            "vt_api_key": settings.VT_API_KEY,
            "hibp_api_key": settings.HIBP_API_KEY
        })
        self.remediation_agent = RemediationAgent(db_client, self.llm_client)
        self.retest_agent = RetestingAgent(db_client, MockRetestEvaluator())
        
        self.agent_routers = {
            AgentType.VAPT: self.vapt_agent.execute_task,
            AgentType.VALIDATION: self.validation_agent.execute_task,
            AgentType.ATTACK_PATH: self.attack_path_agent.execute_task,
            AgentType.THREAT_INTEL: self.threat_intel_agent.execute_task,
            AgentType.REMEDIATION: self.remediation_agent.execute_task,
            AgentType.RETEST: self.retest_agent.execute_task,
        }

    # Safety-net timeout for the event wait. The loop is driven by the DB's
    # task-available signal; this only bounds how long it blocks if a wakeup
    # is ever missed, so the system is self-healing without busy-polling.
    IDLE_WAKE_TIMEOUT = 2.0

    async def run_main_loop(self):
        """The continuous central loop of the AI system.

        Event-driven: the loop dispatches every currently-pending task back to
        back with no artificial delay, then sleeps on the DB's task-available
        event until new work is queued. This minimizes the time between a
        vulnerability being discovered and it being validated/remediated —
        previously each dispatch paid a fixed 0.5s cosmetic delay and each idle
        wave paid a 2s poll, which dominated end-to-end latency.
        """
        logger.info("Starting Orchestrator Main Loop...")
        try:
            while True:
                # 1. Fetch the highest priority pending task
                task = await self.db.get_highest_priority_task()

                if not task:
                    # No work pending. Arm the event and re-check to close the
                    # race where a task is inserted between fetch and clear,
                    # then wait to be woken by insert_task (bounded as a safety net).
                    await self.db.wait_for_task(timeout=self.IDLE_WAKE_TIMEOUT)
                    continue

                logger.info(f"Picked up [Priority {task.priority}] Task for {task.target_agent.value} (Task ID: {task.id[:8]})")

                # 2. Mark as in-progress to prevent other loop iterations from grabbing it
                await self.db.mark_task_in_progress(task.id)

                # 3. Route to the correct agent
                handler = self.agent_routers.get(task.target_agent)

                if handler:
                    # Spawn the agent non-blockingly so the Orchestrator can
                    # immediately dispatch the next pending task concurrently.
                    asyncio.create_task(self._execute_agent(handler, task))
                else:
                    logger.error(f"Unknown agent type requested: {task.target_agent}")
                    await self.db.complete_task(task.id, status="failed")

        except asyncio.CancelledError:
            logger.info("Orchestrator shutting down cleanly...")

    async def _execute_agent(self, handler_func, task: TaskItem):
        """Wrapper to execute agent logic, catch errors, and handle task cleanup."""
        try:
            await handler_func(task.payload)
            await self.db.complete_task(task.id, status="completed")
            logger.info(f"Task {task.id[:8]} completed successfully.")
        except Exception as e:
            logger.error(f"Agent failed on task {task.id[:8]}: {str(e)}")
            await self.db.complete_task(task.id, status="failed")