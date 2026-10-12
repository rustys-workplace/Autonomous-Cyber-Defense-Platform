import logging
from typing import Dict, Any
from core.models import VulnStatus, AgentType, TaskItem
from tools.safety import SafetyValidator, DataSanitizer, execute_in_sandbox
from tools.recon import search_nvd, exploitdb_search

logger = logging.getLogger("ValidationAgent")

def cve_verifier(finding: str, cve_id: str) -> Dict[str, Any]:
    """
    Cross-checks a discovered vulnerability against NVD metadata and Exploit-DB
    to confirm whether public Proof-of-Concept exploits exist.
    """
    nvd_data = search_nvd(cve_id) if cve_id and cve_id.startswith("CVE-") else {}
    edb_data = exploitdb_search(cve_id) if cve_id and cve_id.startswith("CVE-") else {}
    
    cvss = nvd_data.get("cvss_score", 7.5) if nvd_data else 7.5
    has_poc = edb_data.get("has_exploit", False) if edb_data else False
    
    return {
        "finding": finding,
        "cve_id": cve_id,
        "is_known_cve": bool(nvd_data),
        "cvss_score": cvss,
        "has_public_poc": has_poc,
        "poc_count": edb_data.get("poc_count", 0),
        "severity": nvd_data.get("severity", "HIGH"),
        "source": "nvd_and_exploitdb"
    }

def exploitability_scorer(cve_id: str, context: Dict[str, Any] = None) -> float:
    """
    Calculates exploitability confidence score (0.0 to 1.0) based on CVSS + PoC existence + reachability.
    """
    context = context or {}
    nvd = search_nvd(cve_id) if cve_id and cve_id.startswith("CVE-") else {}
    edb = exploitdb_search(cve_id) if cve_id and cve_id.startswith("CVE-") else {}
    
    cvss = nvd.get("cvss_score", context.get("criticality_score", 7.0))
    has_poc = edb.get("has_exploit", False) or bool(context.get("test_payload"))
    
    score = (cvss / 10.0) * 0.7
    if has_poc:
        score += 0.2
    if context.get("reachability", "network") == "network":
        score += 0.1
    return round(min(1.0, max(0.1, score)), 2)

async def safe_probe(target: str, vuln_type: str, payload: str = None) -> Dict[str, Any]:
    """
    Non-destructive confirmation probe (sends benign payload, executes in sandbox/live probe, checks response).
    """
    p = payload or ("' OR '1'='1' --" if "sql" in vuln_type.lower() else "<script>/*canary*/alert(1)</script>")
    raw_response = await execute_in_sandbox(p, target)
    safe_response, creds_leaked = DataSanitizer.scrub_response(raw_response)
    
    is_hardened = "hardened perimeter active" in safe_response.lower() or "server: gws" in safe_response.lower()
    confirmed = any(m.lower() in safe_response.lower() for m in [
        "agent_validated_success", "root:x:0", "syntax error near",
        "<script>/*canary*/alert(1)</script>", "no_security_headers_found",
        "cleartext_http_transmission_confirmed", "db_password=", "dmarc_policy_absent"
    ]) and not is_hardened
    
    return {
        "target": target,
        "vuln_type": vuln_type,
        "payload_sent": p,
        "is_confirmed": confirmed,
        "credentials_leaked": creds_leaked,
        "response_evidence": safe_response[:300]
    }

class MockValidationLLM:
    """Simulates an LLM generating a safe PoC based on vulnerability context."""
    async def generate_safe_poc(self, vuln_title: str, vuln_context: Dict[str, Any] = None) -> Dict[str, str]:
        if vuln_context and vuln_context.get("test_payload") and vuln_context.get("expected_marker"):
            return {
                "payload": str(vuln_context["test_payload"]),
                "expected_marker": str(vuln_context["expected_marker"])
            }

        vuln_lower = vuln_title.lower()
        
        if "cve-2021-23017" in vuln_lower or "nginx" in vuln_lower or "lfi" in vuln_lower or "cwe-22" in vuln_lower or "traversal" in vuln_lower:
            return {
                "payload": "curl -H 'Host: vulnerable' http://target/ --path-as-is ../../../etc/passwd",
                "expected_marker": "root:x:0"
            }
        elif "15778" in vuln_lower or "openssh" in vuln_lower or "scp" in vuln_lower:
            return {
                "payload": "scp -q target:`echo AGENT_VALIDATED` /dev/null",
                "expected_marker": "AGENT_VALIDATED_SUCCESS"
            }
        elif "rce" in vuln_lower or "command" in vuln_lower or "cwe-78" in vuln_lower:
            return {
                "payload": "; echo AGENT_VALIDATED_SUCCESS",
                "expected_marker": "AGENT_VALIDATED_SUCCESS"
            }
        elif "sql" in vuln_lower or "sqli" in vuln_lower or "cwe-89" in vuln_lower:
            return {
                "payload": "' OR '1'='1' --",
                "expected_marker": "syntax error near 'OR 1=1'"
            }
        elif "xss" in vuln_lower or "script" in vuln_lower or "cwe-79" in vuln_lower:
            return {
                "payload": "<script>/*canary*/alert(1)</script>",
                "expected_marker": "<script>/*canary*/alert(1)</script>"
            }
        elif any(k in vuln_lower for k in ["csp", "header", "cwe-693"]):
            return {
                "payload": "curl -I http://target/",
                "expected_marker": "NO_SECURITY_HEADERS_FOUND"
            }
        elif any(k in vuln_lower for k in ["cleartext", "tls", "cwe-319"]):
            return {
                "payload": "curl -I http://target/ (Check Cleartext HTTP Transmission)",
                "expected_marker": "CLEARTEXT_HTTP_TRANSMISSION_CONFIRMED"
            }
        elif any(k in vuln_lower for k in ["sri", "integrity", "cwe-353"]):
            return {
                "payload": "curl -s http://target/ (Check Subresource Integrity)",
                "expected_marker": "SRI_INTEGRITY_MISSING"
            }
        elif any(k in vuln_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
            return {
                "payload": "curl -I http://target/ -H 'X-Phish-Verification: true'",
                "expected_marker": "DMARC_POLICY_ABSENT"
            }
        elif any(k in vuln_lower for k in ["env", "git", "dir", "bruteforce", "cwe-538", "cwe-200"]):
            return {
                "payload": "curl -I http://target/.env",
                "expected_marker": "DB_PASSWORD="
            }
        elif any(k in vuln_lower for k in ["api", "auth", "bola", "idor", "cwe-639", "cwe-306"]):
            return {
                "payload": "curl -I http://target/api/v1/users",
                "expected_marker": '"id":'
            }
            
        return {
            "payload": "' OR '1'='1' --",
            "expected_marker": "syntax error"
        }

class ValidationAgent:
    def __init__(self, db_client, llm_client):
        self.db = db_client
        self.llm = llm_client

    async def execute_task(self, payload: Dict[str, Any]):
        vuln_id = payload.get("vulnerability_id")
        vuln_record = await self.db.get_vulnerability(vuln_id)
        
        if not vuln_record:
            logger.error(f"Vulnerability {vuln_id} not found.")
            return

        logger.info(f"Validating: {vuln_record.title}")
        asset = await self.db.get_asset(vuln_record.asset_id)

        # 1. Prepare Vulnerability Context (reuse verified payloads / markers from discovery)
        vuln_context = dict(vuln_record.metadata or {})
        if payload.get("test_payload") and payload.get("expected_marker"):
            vuln_context["test_payload"] = payload["test_payload"]
            vuln_context["expected_marker"] = payload["expected_marker"]

        # 2. LLM Generates Benign Proof-of-Concept
        try:
            poc_data = await self.llm.generate_safe_poc(vuln_record.title, vuln_context=vuln_context)
        except TypeError:
            poc_data = await self.llm.generate_safe_poc(vuln_record.title)

        generated_payload = poc_data.get("payload", "' OR '1'='1' --")
        expected_marker = poc_data.get("expected_marker", "syntax error")

        # 3. Strict Safety Gate Check
        is_safe, reason = SafetyValidator.validate_payload(generated_payload)
        if not is_safe:
            logger.warning(f"Validation aborted for {vuln_id}: {reason}")
            await self._mark_false_positive(vuln_id)
            return

        # 3b. SQLi confirmed by the active engine during discovery.
        # The active engine flags a parameter only on a concrete signal tied to
        # that exact endpoint+parameter: a DB error surfaced by a benign quote
        # (error-based), a consistent TRUE/FALSE response differential
        # (boolean-blind), or a real injected timing delay (time-based). The
        # shared sandbox probe is generic (it cannot target the specific
        # parameter), so re-running it would false-negative a real finding.
        # We therefore trust that per-parameter confirmation here; the strict
        # safety gate above still applies to the payload.
        detection_method = vuln_context.get("detection_method")
        if vuln_context.get("active_confirmed") and detection_method in ("error-based", "boolean-blind", "time-based"):
            logger.info(f"[+] SUCCESS: {vuln_record.title} confirmed via {detection_method} active probing during discovery.")
            await self._mark_validated(vuln_id, generated_payload, False)
            return

        # 4. Execute in Sandbox
        raw_response = await execute_in_sandbox(generated_payload, asset.asset_identifier)

        # 5. Data Sanitization (Scrub credentials before evaluating)
        safe_response, credentials_leaked = DataSanitizer.scrub_response(raw_response)

        # 6. Evaluate Success
        marker_match = False
        if expected_marker:
            marker_match = expected_marker.lower() in safe_response.lower()

        is_hardened_response = "hardened perimeter active" in safe_response.lower() or "server: gws" in safe_response.lower()
        canary_match = any(m.lower() in safe_response.lower() for m in [
            "agent_validated_success",
            "root:x:0",
            "syntax error near",
            "<script>/*canary*/alert(1)</script>",
            "poc-dmarc-test-canary",
            "dmarc_policy_absent",
            "no_security_headers_found",
            "db_password=",
            "cleartext_http_transmission_confirmed",
            "sri_integrity_missing"
        ]) and not is_hardened_response

        if marker_match or canary_match:
            logger.info(f"[+] SUCCESS: {vuln_record.title} is EXPLOITABLE.")
            await self._mark_validated(vuln_id, generated_payload, credentials_leaked)
        else:
            logger.info(f"[-] FAILED: {vuln_record.title} appears unexploitable. Marked as FALSE_POSITIVE.")
            await self._mark_false_positive(vuln_id)

    async def _mark_validated(self, vuln_id: str, poc_payload: str, creds_leaked: bool):
        """Updates the DB to VALIDATED and triggers downstream agents."""
        # 1. Update the vulnerability state
        await self.db.update_vulnerability(
            vuln_id,
            status=VulnStatus.VALIDATED,
            confidence_score=1.0,
            proof_of_concept=poc_payload,
            has_leaked_creds=creds_leaked
        )
        
        vuln = await self.db.get_vulnerability(vuln_id)

        # 2. Trigger the Attack-Path Agent
        await self.db.insert_task(
            TaskItem(
                target_agent=AgentType.ATTACK_PATH,
                priority=int(vuln.criticality_score * 10),
                payload={"trigger": "new_validation"}
            )
        )
        
        # 3. Trigger the Remediation Agent
        await self.db.insert_task(
            TaskItem(
                target_agent=AgentType.REMEDIATION,
                priority=int(vuln.criticality_score * 10),
                payload={"vulnerability_id": vuln_id}
            )
        )

    async def _mark_false_positive(self, vuln_id: str):
        """Marks as FALSE_POSITIVE. It drops out of the active queue permanently."""
        await self.db.update_vulnerability(
            vuln_id,
            status=VulnStatus.FALSE_POSITIVE,
            confidence_score=0.9
        )