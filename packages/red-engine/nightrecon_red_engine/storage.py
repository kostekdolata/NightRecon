"""Persistent storage for NightRecon results."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from nightrecon_red_engine.api_report import ApiInventoryReport
from nightrecon_red_engine.api_validation_report import ApiValidationReport
from nightrecon_red_engine.browser_report import BrowserDiscoveryReport
from nightrecon_red_engine.discovery_report import HostDiscoveryReport
from nightrecon_red_engine.dast_report import DastAssessmentReport
from nightrecon_red_engine.graphql_report import GraphQLSchemaReport
from nightrecon_red_engine.infrastructure_report import (
    DatabaseInfrastructureAssessmentReport,
    InfrastructureAssessmentReport,
    SmbInfrastructureAssessmentReport,
    WinRmInfrastructureAssessmentReport,
)
from nightrecon_red_engine.pentest_evidence import PentestEvidenceManifest
from nightrecon_red_engine.report import TcpScanReport
from nightrecon_red_engine.session import ScanSession
from nightrecon_red_engine.web_report import WebCrawlReport
from nightrecon_red_engine.web_workflow_report import WebWorkflowReport


class ResultStore:
    """Stores NightRecon result data as JSON files."""

    def __init__(self, root: str | Path = "results") -> None:
        self.root = Path(root)

    def save_session(self, session: ScanSession) -> Path:
        """Save a scan session."""

        return self._save_json(
            session_id=session.session_id,
            data=session.to_dict(),
        )

    def save_report(self, report: TcpScanReport) -> Path:
        """Save a completed TCP scan report."""

        return self._save_json(
            session_id=report.session_id,
            data=report.to_dict(),
        )

    def save_pentest_evidence_manifest(
        self,
        manifest: PentestEvidenceManifest,
    ) -> Path:
        """Save one orchestration evidence manifest beside its phase reports."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{manifest.run_id}-pentest-evidence.json"
        fd, tmp_name = tempfile.mkstemp(
            prefix=output_path.name + ".",
            suffix=".tmp",
            dir=str(self.root),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                json.dump(
                    manifest.to_dict(),
                    file,
                    indent=2,
                    sort_keys=True,
                )
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_name, output_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

        return output_path

    def save_discovery_report(
        self,
        report: HostDiscoveryReport,
    ) -> Path:
        """Save a completed host-discovery report."""

        return self._save_json(
            session_id=report.session_id,
            data=report.to_dict(),
        )

    def save_web_crawl_report(
        self,
        report: WebCrawlReport,
    ) -> Path:
        """Save a completed web-crawl report."""

        return self._save_json(
            session_id=report.session_id,
            data=report.to_dict(),
        )

    def save_web_workflow_report(
        self,
        report: WebWorkflowReport,
    ) -> Path:
        """Save a completed web-workflow report without overwriting crawl data."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-workflow.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_api_inventory_report(
        self,
        report: ApiInventoryReport,
    ) -> Path:
        """Save passive API inventory evidence separately from scan data."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-api.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_api_validation_report(
        self,
        report: ApiValidationReport,
    ) -> Path:
        """Save bounded API validation evidence separately from inventory."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-api-validation.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_graphql_schema_report(
        self,
        report: GraphQLSchemaReport,
    ) -> Path:
        """Save GraphQL schema metadata separately from API inventory."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-graphql.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_dast_assessment_report(
        self,
        report: DastAssessmentReport,
    ) -> Path:
        """Save safe-active DAST evidence separately from crawl data."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-dast.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_infrastructure_assessment_report(
        self,
        report: (
            DatabaseInfrastructureAssessmentReport
            | InfrastructureAssessmentReport
            | SmbInfrastructureAssessmentReport
            | WinRmInfrastructureAssessmentReport
        ),
    ) -> Path:
        """Save credentialed infrastructure evidence without secret material."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-infrastructure.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def save_browser_discovery_report(
        self,
        report: BrowserDiscoveryReport,
    ) -> Path:
        """Save browser discovery evidence separately from crawl data."""

        self.root.mkdir(parents=True, exist_ok=True)
        output_path = self.root / f"{report.session_id}-browser.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path

    def _save_json(
        self,
        session_id: str,
        data: dict,
    ) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)

        output_path = self.root / f"{session_id}.json"
        fd, tmp_name = tempfile.mkstemp(
            prefix=output_path.name + ".",
            suffix=".tmp",
            dir=str(self.root),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                json.dump(
                    data,
                    file,
                    indent=2,
                    sort_keys=True,
                )
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_name, output_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

        return output_path
