"""Orchestrator — owns the assessment pipeline and job lifecycle.

Design decisions:
- Authorization and scope are validated BEFORE any module runs; failures move
  the job to BLOCKED (not FAILED) and are audited.
- Modules run in a fixed order. A failing non-critical module logs a WARNING
  and continues; a failing critical module fails the job.
- Guards: max steps, per-step timeout, retry limit, and a hard_stop flag —
  there is no unbounded loop anywhere in the pipeline.
- Persistence happens through repositories inside the same session.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from agent.analysis.ai_agent import AIAnalysisModule
from agent.analysis.evidence_collector import EvidenceCollectorModule
from agent.analysis.llm_providers import make_llm_provider
from agent.analysis.normalizer import FindingNormalizerModule
from agent.connectors.authorization_manager import AuthorizationManager
from agent.core.audit import audit_logger
from agent.core.config import settings
from agent.core.context import AssessmentContext, PhaseResult, utcnow
from agent.core.enums import AssessmentMode, AssessmentPhase, AssessmentPhaseStatus, JobStatus
from agent.core.exceptions import (
    AuthorizationError,
    CasaError,
    ModuleExecutionError,
    ScopeViolationError,
)
from agent.core.target import ScopeValidator
from agent.modules.active_safe import ActiveSafeModule
from agent.modules.api_security import ApiSecurityModule
from agent.modules.config_analysis import ConfigAnalysisModule
from agent.modules.cookies import CookieSecurityModule
from agent.modules.cors_analyzer import CorsAnalyzerModule
from agent.modules.discovery import DiscoveryModule
from agent.modules.dns_security import DnsSecurityModule
from agent.modules.headers import HeadersModule
from agent.modules.http_config import HttpConfigModule
from agent.modules.info_disclosure import InfoDisclosureModule
from agent.modules.recon import ReconModule
from agent.modules.tech_detection import TechDetectionModule
from agent.modules.tls_analysis import TlsAnalysisModule
from agent.modules.tool_runner import ToolRunnerModule
from agent.modules.osv_enrichment import OsvEnrichmentModule
from agent.modules.vuln_correlation import VulnCorrelationModule
from agent.modules.waf_detect import WafDetectModule
from agent.modules.web_checks import WebChecksModule
from agent.risk.engine import RiskEngine
from agent.storage import repositories as repo

logger = logging.getLogger("casa.orchestrator")

# Module registry: every pipeline module is declared here exactly once.
# Profiles (QUICK/STANDARD/DEEP) select from these; tail stages always run.
MODULE_REGISTRY: dict[str, tuple] = {
    "recon": lambda v, s: ReconModule(v),
    "discovery": lambda v, s: DiscoveryModule(v),
    "tech_detection": lambda v, s: TechDetectionModule(v),
    "config_analysis": lambda v, s: ConfigAnalysisModule(v),
    "headers": lambda v, s: HeadersModule(v),
    "cookies": lambda v, s: CookieSecurityModule(v),
    "http_config": lambda v, s: HttpConfigModule(v),
    "tls_analysis": lambda v, s: TlsAnalysisModule(v),
    "cors_analyzer": lambda v, s: CorsAnalyzerModule(v),
    "api_security": lambda v, s: ApiSecurityModule(v),
    "info_disclosure": lambda v, s: InfoDisclosureModule(v),
    "web_checks": lambda v, s: WebChecksModule(v),
    "active_safe": lambda v, s: ActiveSafeModule(v),
    "dns_security": lambda v, s: DnsSecurityModule(v),
    "vuln_correlation": lambda v, s: VulnCorrelationModule(v),
    "waf_detect": lambda v, s: WafDetectModule(v),
    "osv_enrichment": lambda v, s: OsvEnrichmentModule(v),
    "tool_runner": lambda v, s: ToolRunnerModule(v),
}
_TAIL_FACTORIES: list = [
    lambda v, s: EvidenceCollectorModule(v),
    lambda v, s: FindingNormalizerModule(v),
]

# Assessment profiles (Phase 14). Each profile explicitly lists the modules
# that execute, in order. TAIL stages (evidence/normalization) always run.
PROFILES: dict[str, list[str]] = {
    AssessmentMode.QUICK.value: [
        "recon",
        "tech_detection",
        "headers",
        "tls_analysis",
        "waf_detect",
        "tool_runner",   # QUICK tool map: WhatWeb only (registry filters)
    ],
    AssessmentMode.STANDARD.value: [
        "recon",
        "discovery",
        "tech_detection",
        "config_analysis",
        "headers",
        "cookies",
        "http_config",
        "tls_analysis",
        "cors_analyzer",
        "info_disclosure",
        "web_checks",
        "dns_security",
        "waf_detect",
        "vuln_correlation",
        "osv_enrichment",  # CVE advisories via OSV.dev (degrades offline)
        "tool_runner",   # STANDARD tool map: whatweb/nikto/nuclei (+nmap in DEEP)
    ],
    AssessmentMode.DEEP.value: [
        "recon",
        "discovery",
        "tech_detection",
        "config_analysis",
        "headers",
        "cookies",
        "http_config",
        "tls_analysis",
        "cors_analyzer",
        "api_security",
        "info_disclosure",
        "web_checks",
        "active_safe",
        "dns_security",
        "waf_detect",
        "vuln_correlation",
        "osv_enrichment",
        "tool_runner",   # DEEP tool map: + nmap + gobuster + ffuf (surface enrichment)
    ],
}


def _profile_module_factories(profile: str) -> list:
    names = PROFILES.get(profile) or PROFILES[AssessmentMode.STANDARD.value]
    return [MODULE_REGISTRY[n] for n in names if n in MODULE_REGISTRY]


class Orchestrator:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._llm = make_llm_provider()

    # ------------------------------------------------------------------ run

    async def run_job(self, job_id: UUID) -> dict[str, Any]:
        job = await repo.get_job(self._session, str(job_id))
        target = await repo.get_target(self._session, job.target_id)
        await repo.update_job_status(self._session, job.id, JobStatus.RUNNING.value)
        audit_logger.emit(
            "JOB_STARTED",
            job_id=job.id,
            target=target.url,
            details={"trigger": job.trigger},
        )
        await repo.record_audit(
            self._session,
            "JOB_STARTED",
            job_id=job.id,
            target=target.url,
            details={"trigger": job.trigger},
        )

        # --- Authorization Gate (before anything else touches the target) ---
        ctx: AssessmentContext | None = None
        try:
            authz, validator = await self._authorize(job, target)
        except (AuthorizationError, ScopeViolationError) as exc:
            await self._fail(
                job, target, None, JobStatus.BLOCKED.value, f"authorization gate: {exc}"
            )
            return {
                "job_id": str(job.id),
                "assessment_id": None,
                "status": JobStatus.BLOCKED.value,
                "error": f"authorization gate: {exc}",
            }

        assessment = await repo.create_assessment(
            self._session,
            job=job,
            target=target,
            scope_snapshot={
                "allowed_domains": authz.allowed_domains,
                "allowed_paths": authz.allowed_paths,
                "excluded_targets": authz.excluded_targets,
                "window_start": authz.window_start.isoformat() if authz.window_start else None,
                "window_end": authz.window_end.isoformat() if authz.window_end else None,
                "authorized_by": authz.authorized_by,
                "authorization_reference": authz.authorization_reference,
            },
        )

        ctx = AssessmentContext(
            job_id=job.id if isinstance(job.id, UUID) else UUID(job.id),
            assessment_id=(
                assessment.id if isinstance(assessment.id, UUID) else UUID(assessment.id)
            ),
            target_url=target.url,
            base_domain=AuthorizationManager.base_domain_of(target.url),
            scope={
                "allowed_domains": authz.allowed_domains,
                "allowed_paths": authz.allowed_paths,
                "excluded_targets": authz.excluded_targets,
                "authorized_by": authz.authorized_by,
                "authorization_reference": authz.authorization_reference,
                "profile": str(getattr(job, "profile", "") or AssessmentMode.STANDARD.value),
            },
            trigger=job.trigger,
            previous_assessment_id=job.previous_assessment_id,
            mode=str(getattr(job, "profile", "") or AssessmentMode.STANDARD.value),
        )

        if job.previous_assessment_id:
            prev = await repo.get_assessment(self._session, job.previous_assessment_id)
            prev_rows = await repo.list_findings(self._session, prev.id)
            ctx.baseline_findings = [
                {
                    "id": r.id,
                    "fingerprint": r.fingerprint,
                    "title": r.title,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "status": r.status,
                    "false_positive": r.false_positive,
                    "risk_score": r.risk_score,
                }
                for r in prev_rows
                if not r.false_positive
            ]

        overall_status = JobStatus.COMPLETED.value
        error_message: str | None = None

        try:
            await self._run_pipeline(ctx, validator)

            await repo.update_job_status(self._session, job.id, JobStatus.ANALYZING.value)
            await self._persist_evidence(ctx)
            await self._run_risk_and_ai(ctx)

            # Post-normalization enrichment (BEFORE persistence so the DB,
            # API and reports all carry the same enriched metadata):
            #  - MITRE ATT&CK technique annotations
            #  - full what/why/how explanations per finding
            from agent.analysis.attack_mapping import AttackMappingModule

            attack_mapper = AttackMappingModule(validator)
            await attack_mapper.run(ctx)

            from agent.analysis.explanation import ExplanationModule

            explainer = ExplanationModule(validator)
            await explainer.run(ctx)

            # Persist normalized + risk-scored + AI-annotated + enriched
            # findings BEFORE verification/reports so downstream stages and
            # the DB agree.
            await repo.save_findings(self._session, str(ctx.assessment_id), ctx.findings)

            verification = await self._run_verification(ctx)

            await repo.update_job_status(self._session, job.id, JobStatus.VERIFYING.value)

            from agent.analysis.attack_surface import build_attack_surface
            from agent.reports.generator import ReportGenerator

            generator = ReportGenerator(self._session)
            await generator.generate(ctx)

            # SARIF 2.1.0 artifact (GitHub Code Scanning compatible)
            from agent.reports.sarif import sarif_json

            await repo.save_artifact(
                self._session,
                str(ctx.assessment_id),
                fmt="sarif",
                path="",
                content=sarif_json(
                    ctx.target_url,
                    ctx.findings,
                    (ctx.risk_summary or {}).get("security_score"),
                ),
            )

            await repo.finish_assessment(
                self._session,
                str(ctx.assessment_id),
                status="COMPLETED",
                security_score=(ctx.risk_summary or {}).get("security_score"),
                risk_summary=ctx.risk_summary,
                ai_summary=ctx.ai_summary,
                verification_summary=verification,
                attack_surface=build_attack_surface(ctx),
            )
            await repo.update_job_status(self._session, job.id, JobStatus.COMPLETED.value)
            audit_logger.emit(
                "JOB_COMPLETED",
                job_id=job.id,
                target=target.url,
                details={"assessment_id": str(ctx.assessment_id)},
            )
            await repo.record_audit(
                self._session,
                "JOB_COMPLETED",
                job_id=job.id,
                target=target.url,
                details={
                    "assessment_id": str(ctx.assessment_id),
                    "findings": len(ctx.findings),
                },
            )

            # Webhook notification (never raises; delivery is best-effort)
            from agent.analysis.notify import send_webhook

            dist = (ctx.risk_summary or {}).get("distribution", {})
            webhook_payload = {
                "job_id": str(job.id),
                "assessment_id": str(ctx.assessment_id),
                "target": target.url,
                "status": JobStatus.COMPLETED.value,
                "security_score": (ctx.risk_summary or {}).get("security_score"),
                "findings": len(ctx.findings),
                "severity_distribution": dist,
            }
            receipt = await send_webhook("JOB_COMPLETED", webhook_payload)
            await repo.record_audit(
                self._session,
                "WEBHOOK_ATTEMPTED",
                job_id=job.id,
                target=target.url,
                outcome="OK" if receipt.get("sent") else "SKIPPED",
                details={"receipt": receipt},
            )
        except ScopeViolationError as exc:
            overall_status = JobStatus.BLOCKED.value
            error_message = f"scope violation: {exc}"
        except AuthorizationError as exc:
            overall_status = JobStatus.BLOCKED.value
            error_message = f"authorization error: {exc}"
        except ModuleExecutionError as exc:
            overall_status = JobStatus.FAILED.value
            error_message = str(exc)
        except CasaError as exc:
            overall_status = JobStatus.FAILED.value
            error_message = str(exc)
        except asyncio.TimeoutError:
            overall_status = JobStatus.FAILED.value
            error_message = "job exceeded total timeout"
        except Exception as exc:  # noqa: BLE001 - last-resort guard for the worker loop
            overall_status = JobStatus.FAILED.value
            error_message = f"unexpected error: {exc}"

        if overall_status != JobStatus.COMPLETED.value:
            await self._fail(job, target, ctx, overall_status, error_message)

        return {
            "job_id": str(job.id),
            "assessment_id": str(ctx.assessment_id) if ctx is not None else None,
            "status": overall_status,
            "error": error_message,
        }

    # ------------------------------------------------------------- helpers

    async def _fail(
        self,
        job,
        target,
        ctx: AssessmentContext | None,
        status: str,
        error: str | None,
    ) -> None:
        await repo.update_job_status(self._session, job.id, status, error)
        if ctx is not None:
            try:
                await repo.finish_assessment(
                    self._session,
                    str(ctx.assessment_id),
                    status=status,
                    security_score=None,
                    risk_summary=None,
                    ai_summary=None,
                )
            except CasaError:
                pass
        audit_logger.emit(
            "JOB_" + status,
            job_id=job.id,
            target=target.url,
            outcome=status,
            details={"error": error},
        )
        await repo.record_audit(
            self._session,
            "JOB_" + status,
            job_id=job.id,
            target=target.url,
            outcome=status,
            details={"error": error},
        )

    async def _persist_evidence(self, ctx: AssessmentContext) -> None:
        bundle = ctx.raw_results.get("evidence_bundle") or []
        for item in bundle:
            await repo.save_evidence(
                self._session,
                str(ctx.assessment_id),
                kind=item.get("kind", "OTHER"),
                source=item.get("source", ""),
                url=item.get("url", ""),
                content=item.get("content") or {},
            )

    # ------------------------------------------------------------- pipeline

    async def _run_pipeline(self, ctx: AssessmentContext, validator: ScopeValidator) -> None:
        if ctx.step_count > settings.job_max_steps:
            raise ModuleExecutionError("job_max_steps exceeded")

        profile = str(ctx.scope.get("profile") or AssessmentMode.STANDARD.value).upper()
        factories = _profile_module_factories(profile) + _TAIL_FACTORIES
        for factory in factories:
            if ctx.hard_stop:
                raise ModuleExecutionError("hard stop requested; aborting pipeline")
            module = factory(validator, ctx.scope)
            started = time.monotonic()
            phase = PhaseResult(
                phase=module.phase or module.name,
                module=module.name,
                status=AssessmentPhaseStatus.OK.value,
                started_at=utcnow(),
            )
            if not module.applies(ctx):
                phase.status = AssessmentPhaseStatus.SKIPPED.value
                phase.summary = "not applicable for this target"
                phase.finished_at = utcnow()
                phase.duration_ms = int((time.monotonic() - started) * 1000)
                ctx.phases.append(phase)
                continue

            attempt = 0
            while True:
                attempt += 1
                try:
                    await asyncio.wait_for(
                        module.run(ctx), timeout=settings.job_step_timeout_seconds
                    )
                    break
                except asyncio.TimeoutError:
                    error = (
                        f"module {module.name} timed out after "
                        f"{settings.job_step_timeout_seconds}s"
                    )
                    if attempt <= settings.job_module_retries:
                        logger.warning("%s; retrying", error)
                        continue
                    phase.status = AssessmentPhaseStatus.FAILED.value
                    phase.error = error
                    break
                except ScopeViolationError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    error = (
                        f"module {module.name} failed: "
                        f"{type(exc).__name__}: {exc or '(no message)'}"
                    )
                    if attempt <= settings.job_module_retries:
                        logger.warning("%s; retrying", error)
                        continue
                    phase.status = AssessmentPhaseStatus.FAILED.value
                    phase.error = error
                    break

            phase.finished_at = utcnow()
            phase.duration_ms = int((time.monotonic() - started) * 1000)
            if phase.status == AssessmentPhaseStatus.FAILED.value:
                if module.critical:
                    raise ModuleExecutionError(phase.error or "critical module failed")
                logger.warning("non-critical module failed; continuing: %s", phase.error)
                phase.status = AssessmentPhaseStatus.WARNING.value
            ctx.phases.append(phase)
            ctx.step_count += 1
            await repo.record_audit(
                self._session,
                "MODULE_EXECUTED",
                job_id=str(ctx.job_id),
                target=ctx.target_url,
                outcome=phase.status,
                details={
                    "module": module.name,
                    "phase": phase.phase,
                    "duration_ms": phase.duration_ms,
                },
            )

    async def _run_risk_and_ai(self, ctx: AssessmentContext) -> None:
        engine = RiskEngine()
        ctx.risk_summary = engine.compute(ctx.findings)

        if settings.ai_analysis_enabled:
            started = time.monotonic()
            ai_module = AIAnalysisModule(None, self._llm)
            phase = PhaseResult(
                phase=AssessmentPhase.AI_ANALYSIS.value,
                module=ai_module.name,
                status=AssessmentPhaseStatus.OK.value,
                started_at=utcnow(),
            )
            try:
                await asyncio.wait_for(
                    ai_module.run(ctx), timeout=settings.job_step_timeout_seconds
                )
            except asyncio.TimeoutError:
                phase.status = AssessmentPhaseStatus.WARNING.value
                phase.error = "ai analysis timed out"
                ctx.ai_summary = {"error": "ai_analysis_timeout", "degraded": True}
            except Exception as exc:  # noqa: BLE001
                phase.status = AssessmentPhaseStatus.WARNING.value
                phase.error = str(exc)
                ctx.ai_summary = {"error": str(exc), "degraded": True}
            phase.finished_at = utcnow()
            phase.duration_ms = int((time.monotonic() - started) * 1000)
            ctx.phases.append(phase)

    async def _run_verification(self, ctx: AssessmentContext) -> dict[str, Any] | None:
        if not ctx.baseline_findings:
            return None
        from agent.verification.engine import VerificationEngine

        engine = VerificationEngine()
        result = engine.compare(ctx.baseline_findings, ctx.findings)
        ctx.verification_summary = result
        return result

    # -------------------------------------------------------------- gate

    async def _authorize(self, job, target) -> tuple[Any, ScopeValidator]:
        try:
            manager = AuthorizationManager(self._session)
            authz, validator = await manager.resolve_for_target_url(target.url)
            audit_logger.emit(
                "AUTHORIZATION_GATE_PASSED",
                job_id=job.id,
                target=target.url,
                details={"authorization_id": authz.id},
            )
            return authz, validator
        except (AuthorizationError, ScopeViolationError) as exc:
            audit_logger.emit(
                "AUTHORIZATION_GATE_REJECTED",
                job_id=job.id,
                target=target.url,
                outcome="BLOCKED",
                details={"reason": str(exc)},
            )
            raise
