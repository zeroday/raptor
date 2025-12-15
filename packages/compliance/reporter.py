#!/usr/bin/env python3
"""
ASVS Compliance Reporter

Generates comprehensive ASVS compliance reports in JSON and Markdown formats.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add paths for cross-package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger

logger = get_logger()


class ComplianceReporter:
    """Generates ASVS compliance reports."""

    def __init__(self, assessments: Dict[str, Any], asvs_version: str, level: int):
        """
        Initialize reporter with assessment data.

        Args:
            assessments: Compliance assessment results
            asvs_version: ASVS version (e.g., "5.0.0")
            level: Verification level assessed
        """
        self.assessments = assessments
        self.asvs_version = asvs_version
        self.level = level

    def generate_compliance_report(self, out_dir: Path) -> Path:
        """
        Generate JSON compliance report.

        Args:
            out_dir: Output directory

        Returns:
            Path to generated JSON report
        """
        out_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "asvs_version": self.asvs_version,
            "verification_level": self.level,
            "assessment_date": self.assessments.get("assessment_date", datetime.now().isoformat()),
            "overall_compliance": self.assessments.get("overall_compliance", {}).get("overall_compliance", 0.0),
            "level_achieved": self.assessments.get("overall_compliance", {}).get("level_achieved", 0),
            "categories": {},
            "gap_analysis": self._generate_gap_analysis(),
        }

        # Add category details
        overall = self.assessments.get("overall_compliance", {})
        for category_id, category_summary in overall.get("categories", {}).items():
            report["categories"][category_id] = {
                "name": category_summary.get("name", category_id),
                "compliance": category_summary.get("compliance", 0.0),
                "requirements_met": category_summary.get("requirements_met", 0),
                "requirements_total": category_summary.get("requirements_total", 0),
                "requirements": category_summary.get("requirements", []),
            }

        # Save JSON report
        report_path = out_dir / "asvs_compliance_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON compliance report saved to {report_path}")
        return report_path

    def generate_markdown_report(self, out_dir: Path) -> Path:
        """
        Generate human-readable Markdown compliance report.

        Args:
            out_dir: Output directory

        Returns:
            Path to generated Markdown report
        """
        out_dir.mkdir(parents=True, exist_ok=True)

        overall = self.assessments.get("overall_compliance", {})
        overall_compliance = overall.get("overall_compliance", 0.0)
        level_achieved = overall.get("level_achieved", 0)
        target_level = overall.get("target_level", self.level)

        # Build Markdown report
        md_lines = [
            "# ASVS Compliance Report",
            "",
            f"**Version**: {self.asvs_version}  ",
            f"**Level Assessed**: Level {self.level}  ",
            f"**Overall Compliance**: {overall_compliance}%  ",
            f"**Level Achieved**: Level {level_achieved} (Target: Level {target_level})  ",
            f"**Assessment Date**: {self.assessments.get('assessment_date', datetime.now().isoformat())}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"Overall compliance with OWASP ASVS v{self.asvs_version} Level {self.level}: **{overall_compliance}%**",
            "",
            f"- **Requirements Met**: {overall.get('requirements_met', 0)}",
            f"- **Requirements Failed**: {overall.get('requirements_failed', 0)}",
            f"- **Total Requirements**: {overall.get('total_requirements', 0)}",
            "",
            "---",
            "",
            "## Category Breakdown",
            "",
        ]

        # Add category summaries
        for category_id, category_summary in overall.get("categories", {}).items():
            category_name = category_summary.get("name", category_id)
            compliance = category_summary.get("compliance", 0.0)
            met = category_summary.get("requirements_met", 0)
            total = category_summary.get("requirements_total", 0)

            status_icon = "✅" if compliance >= 80 else "❌" if compliance < 60 else "⚠️"

            md_lines.extend([
                f"### {category_name} ({category_id})",
                "",
                f"**Compliance**: {compliance}% ({met}/{total} requirements met) {status_icon}",
                "",
            ])

            # Add failed requirements
            failed_reqs = [
                req for req in category_summary.get("requirements", [])
                if req.get("status") == "FAIL"
            ]

            if failed_reqs:
                md_lines.append("**Failed Requirements:**")
                md_lines.append("")
                for req in failed_reqs[:10]:  # Limit to first 10
                    req_id = req.get("requirement_id", "")
                    md_lines.append(f"- **{req_id}**: {req.get('recommendation', '')}")
                if len(failed_reqs) > 10:
                    md_lines.append(f"- ... and {len(failed_reqs) - 10} more")
                md_lines.append("")

            md_lines.append("---")
            md_lines.append("")

        # Add detailed requirement assessments
        md_lines.extend([
            "## Detailed Requirement Assessments",
            "",
        ])

        for category_id, category_summary in overall.get("categories", {}).items():
            category_name = category_summary.get("name", category_id)
            md_lines.extend([
                f"### Category: {category_name} ({category_id})",
                "",
            ])

            for req in category_summary.get("requirements", []):
                req_id = req.get("requirement_id", "")
                status = req.get("status", "UNKNOWN")
                description = req.get("requirement_description", "")

                status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚪"

                md_lines.extend([
                    f"#### {req_id}: {description[:100]}",
                    f"**Status**: {status_icon} {status}",
                    "",
                ])

                if status == "FAIL":
                    findings = req.get("findings", [])
                    if findings:
                        md_lines.append("**Findings:**")
                        md_lines.append("")
                        for finding in findings[:5]:  # Limit to first 5
                            finding_msg = finding.get("message", "") or finding.get("vulnerability_type", "")
                            md_lines.append(f"- {finding_msg[:200]}")
                        if len(findings) > 5:
                            md_lines.append(f"- ... and {len(findings) - 5} more findings")
                        md_lines.append("")

                    recommendation = req.get("recommendation", "")
                    if recommendation:
                        md_lines.extend([
                            "**Recommendation**:",
                            f"{recommendation}",
                            "",
                        ])

                md_lines.append("---")
                md_lines.append("")

        # Add gap analysis
        gap_analysis = self._generate_gap_analysis()
        if gap_analysis.get("critical_gaps"):
            md_lines.extend([
                "## Gap Analysis",
                "",
                "### Critical Gaps",
                "",
            ])

            for gap in gap_analysis.get("critical_gaps", [])[:20]:
                md_lines.append(f"- **{gap.get('requirement_id', '')}**: {gap.get('description', '')}")
                md_lines.append(f"  - Recommendation: {gap.get('recommendation', '')}")
                md_lines.append("")

        # Add recommendations
        if gap_analysis.get("recommendations"):
            md_lines.extend([
                "### Recommendations",
                "",
            ])

            for rec in gap_analysis.get("recommendations", [])[:20]:
                md_lines.append(f"- {rec}")
                md_lines.append("")

        # Save Markdown report
        report_path = out_dir / "asvs_compliance_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))

        logger.info(f"Markdown compliance report saved to {report_path}")
        return report_path

    def _generate_gap_analysis(self) -> Dict[str, Any]:
        """Generate gap analysis from assessments."""
        overall = self.assessments.get("overall_compliance", {})
        critical_gaps = []
        recommendations = []

        for category_id, category_summary in overall.get("categories", {}).items():
            for req in category_summary.get("requirements", []):
                if req.get("status") == "FAIL":
                    critical_gaps.append({
                        "requirement_id": req.get("requirement_id", ""),
                        "description": req.get("requirement_description", ""),
                        "recommendation": req.get("recommendation", ""),
                        "findings_count": len(req.get("findings", [])),
                    })

                    rec = req.get("recommendation", "")
                    if rec and rec not in recommendations:
                        recommendations.append(rec)

        return {
            "critical_gaps": critical_gaps,
            "recommendations": recommendations,
            "total_gaps": len(critical_gaps),
        }


# Convenience functions
def generate_compliance_report(
    assessments: Dict[str, Any], asvs_version: str, level: int, out_dir: Path
) -> Path:
    """Generate JSON compliance report."""
    reporter = ComplianceReporter(assessments, asvs_version, level)
    return reporter.generate_compliance_report(out_dir)


def generate_markdown_report(
    assessments: Dict[str, Any], asvs_version: str, level: int, out_dir: Path
) -> Path:
    """Generate Markdown compliance report."""
    reporter = ComplianceReporter(assessments, asvs_version, level)
    return reporter.generate_markdown_report(out_dir)
