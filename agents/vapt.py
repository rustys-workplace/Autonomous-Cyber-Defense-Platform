import asyncio
import logging
from typing import Dict, Any, List
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, TaskItem, AgentType
from tools.scanners import (
    run_nmap,
    port_scanner,
    service_fingerprint,
    web_crawler,
    header_analyzer,
    ssl_checker,
    dir_bruteforce,
    api_endpoint_scanner,
    sqli_scanner,
    query_nvd,
    scan_web_vulnerabilities,
    scan_phishing,
    scan_owasp_top10,
    map_to_mitre
)

logger = logging.getLogger("VAPTAgent")

class MockLLMClient:
    """Simulates an LLM parsing terminal output into JSON/CPE formats."""
    async def extract_cpe_from_nmap(self, nmap_output: str) -> List[str]:
        cpes = []
        output_lower = nmap_output.lower()
        if "nginx" in output_lower and ("open" in output_lower or "port" in output_lower):
            cpes.append("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        if ("openssh" in output_lower or "ssh" in output_lower) and ("open" in output_lower or "port" in output_lower):
            cpes.append("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")
        if "apache" in output_lower and ("open" in output_lower or "port" in output_lower):
            cpes.append("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        return cpes

class VAPTAgent:
    def __init__(self, db_client, llm_client, nvd_api_key: str = None):
        self.db = db_client
        self.llm = llm_client
        self.nvd_api_key = nvd_api_key
        self._seen_titles = set()

    async def execute_task(self, payload: Dict[str, Any]):
        """The main fast, concurrent execution flow for Recon and Discovery."""
        asset_id = payload.get("asset_id")
        
        # 1. ENFORCE SCOPE (Critical Security Boundary)
        asset: TargetAsset = await self.db.get_asset(asset_id)
        if not asset:
            logger.error(f"Asset {asset_id} not found. Aborting.")
            return
            
        if not asset.is_authorized:
            logger.warning(f"SECURITY BLOCK: Asset {asset.asset_identifier} is not authorized for testing.")
            return

        target = asset.asset_identifier
        logger.info(f"Starting VAPT scan on authorized target: {target}")

        # 2. Concurrently execute network and web reconnaissance
        is_web = asset.layer in ["Web", "Cloud"] or "http" in target.lower() or any(c.isalpha() for c in target)

        # Network scan task
        network_task = asyncio.create_task(port_scanner(target))

        # Web scan tasks (if web surface)
        web_tasks = []
        if is_web:
            web_tasks.append(asyncio.create_task(web_crawler(target)))
            web_tasks.append(asyncio.create_task(header_analyzer(target)))
            web_tasks.append(asyncio.create_task(ssl_checker(target)))
            web_tasks.append(asyncio.create_task(scan_owasp_top10(target)))
            web_tasks.append(asyncio.create_task(dir_bruteforce(target)))
            web_tasks.append(asyncio.create_task(api_endpoint_scanner(target)))
            web_tasks.append(asyncio.create_task(scan_phishing(target)))
            web_tasks.append(asyncio.create_task(sqli_scanner(target)))

        # Wait for network scan
        nmap_output = await network_task
        if nmap_output:
            cpe_list = await self.llm.extract_cpe_from_nmap(nmap_output)
            logger.info(f"LLM extracted {len(cpe_list)} services for vulnerability correlation.")
            for cpe in cpe_list:
                vulnerabilities = await query_nvd(cpe, self.nvd_api_key)
                for vuln in vulnerabilities:
                    await self._queue_validation_task(asset.id, cpe, vuln)

        # Wait for all web tasks concurrently
        if web_tasks:
            results = await asyncio.gather(*web_tasks, return_exceptions=True)
            crawler_res = results[0] if len(results) > 0 and not isinstance(results[0], Exception) else {}
            header_res = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else {}
            ssl_res = results[2] if len(results) > 2 and not isinstance(results[2], Exception) else {}
            owasp_res = results[3] if len(results) > 3 and not isinstance(results[3], Exception) else {}
            dir_res = results[4] if len(results) > 4 and not isinstance(results[4], Exception) else {}
            api_res = results[5] if len(results) > 5 and not isinstance(results[5], Exception) else {}
            phish_res = results[6] if len(results) > 6 and not isinstance(results[6], Exception) else {}
            sqli_res = results[7] if len(results) > 7 and not isinstance(results[7], Exception) else {}

            # Process crawler findings (SQLi, XSS, etc.)
            if isinstance(crawler_res, dict):
                for c_vuln in crawler_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, c_vuln, source="TOOL_WEB_CRAWLER")

            # Process header findings
            if isinstance(header_res, dict):
                for h_vuln in header_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, h_vuln, source="TOOL_HEADER_ANALYZER")

            # Process SSL findings
            if isinstance(ssl_res, dict):
                for s_vuln in ssl_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, s_vuln, source="TOOL_SSL_CHECKER")

            # Process OWASP Top 10 findings
            if isinstance(owasp_res, dict):
                for o_vuln in owasp_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, o_vuln, source="TOOL_OWASP_TOP10")

            # Process Directory findings
            if isinstance(dir_res, dict):
                for d_vuln in dir_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, d_vuln, source="TOOL_DLR_BRUTEFORCE")

            # Process API findings
            if isinstance(api_res, dict):
                for a_vuln in api_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, a_vuln, source="TOOL_API_SCANNER")

            # Process Phishing findings
            if isinstance(phish_res, dict):
                for p_vuln in phish_res.get("vulnerabilities", []):
                    p_vuln["phishing_score"] = phish_res.get("phishing_score", 45)
                    await self._queue_web_validation_task(asset.id, p_vuln, source="TOOL_PHISHING_DETECTOR", layer="Email/OSINT")

            # Process dedicated active SQLi engine findings (error/boolean/time-based)
            if isinstance(sqli_res, dict):
                for q_vuln in sqli_res.get("vulnerabilities", []):
                    await self._queue_web_validation_task(asset.id, q_vuln, source="TOOL_SQLI_ACTIVE")

        logger.info(f"VAPT scan complete for {target}.")

    async def _queue_validation_task(self, asset_id: str, cpe: str, vuln: Dict):
        """Creates the DB record and pushes it to the Orchestrator Queue."""
        cve_id = vuln['cve_id']
        cvss_score = vuln['cvss_score']
        title = f"Potential {cve_id} in {cpe.split(':')[4]}"
        mitre_data = map_to_mitre(title)
        
        meta = {
            "mitre": mitre_data,
            "cve_id": cve_id,
            "cpe": cpe,
            "test_payload": vuln.get("test_payload"),
            "expected_marker": vuln.get("expected_marker")
        }

        # Write to Shared Database as UNVALIDATED
        vuln_record = VulnerabilityRecord(
            asset_id=asset_id,
            title=title,
            criticality_score=cvss_score,
            layer="Network",
            status=VulnStatus.UNVALIDATED, 
            discovery_source="TOOL_EVIDENCE",
            confidence_score=0.3,
            metadata=meta
        )
        
        record_id = await self.db.insert_vulnerability(vuln_record)
        priority = int(cvss_score * 10)
        
        task = TaskItem(
            target_agent=AgentType.VALIDATION,
            priority=priority,
            payload={
                "vulnerability_id": record_id,
                "cve_id": cve_id,
                "context": vuln['description'],
                "test_payload": vuln.get("test_payload"),
                "expected_marker": vuln.get("expected_marker")
            }
        )
        
        await self.db.insert_task(task)
        logger.info(f"Found {cve_id} (CVSS: {cvss_score}). Queued for Validation with Priority {priority}.")

    async def _queue_web_validation_task(self, asset_id: str, vuln: Dict, source: str = "TOOL_WEB_SCANNER", layer: str = "Web"):
        """Creates the DB record for web vulnerabilities (SQLi, XSS, headers, API, directory, phishing, OWASP) and queues for validation."""
        title = vuln.get("title", "Web Application Flaw")
        cwe_id = vuln.get("cwe_id", "CWE-Web")
        norm_title = f"{title} ({cwe_id})"

        if not hasattr(self, "_seen_titles"):
            self._seen_titles = set()
        if (asset_id, norm_title) in self._seen_titles:
            return
        self._seen_titles.add((asset_id, norm_title))

        cvss_score = float(vuln.get("cvss_score", 7.5))
        mitre_data = map_to_mitre(f"{title} {cwe_id} {vuln.get('mitre_technique', '')}")
        
        meta = {
            "mitre": mitre_data,
            "path": vuln.get("path"),
            "endpoint": vuln.get("endpoint"),
            "parameter": vuln.get("parameter"),
            "phishing_score": vuln.get("phishing_score"),
            "test_payload": vuln.get("test_payload"),
            "expected_marker": vuln.get("expected_marker"),
            "owasp_category": vuln.get("owasp_category"),
            "remediation": vuln.get("remediation"),
            "detection_method": vuln.get("detection_method"),
            "active_confirmed": vuln.get("active_confirmed", False),
            "evidence": vuln.get("evidence"),
        }
        
        vuln_record = VulnerabilityRecord(
            asset_id=asset_id,
            title=f"{title} ({cwe_id})",
            criticality_score=cvss_score,
            layer=layer,
            status=VulnStatus.UNVALIDATED,
            discovery_source=source,
            confidence_score=0.5,
            metadata=meta
        )
        record_id = await self.db.insert_vulnerability(vuln_record)
        priority = int(cvss_score * 10)
        
        task = TaskItem(
            target_agent=AgentType.VALIDATION,
            priority=priority,
            payload={
                "vulnerability_id": record_id,
                "cve_id": cwe_id,
                "context": f"{title}. Test payload: {vuln.get('test_payload', vuln.get('remediation', 'Standard web probe'))}",
                "test_payload": vuln.get("test_payload"),
                "expected_marker": vuln.get("expected_marker")
            }
        )
        await self.db.insert_task(task)
        logger.info(f"Queued {title} ({cwe_id}, CVSS: {cvss_score}) for Validation with Priority {priority}.")