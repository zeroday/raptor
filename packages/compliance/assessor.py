#!/usr/bin/env python3
"""
ASVS Compliance Assessor

Assesses compliance status for each ASVS requirement and calculates compliance scores.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime

# Add paths for cross-package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger
from packages.compliance.asvs_loader import get_requirement_by_id
from packages.compliance.asvs_mapper import ASVSMapper

logger = get_logger()


class ComplianceAssessor:
    """Assesses ASVS compliance based on findings."""

    def __init__(self, asvs_data: Dict[str, Any]):
        """
        Initialize assessor with ASVS data.

        Args:
            asvs_data: Loaded ASVS requirements
        """
        self.asvs_data = asvs_data
        self.mapper = ASVSMapper(asvs_data)

    def assess_requirement_compliance(
        self,
        req_id: str,
        findings: List[Dict],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Assess compliance status for a specific ASVS requirement.

        Args:
            req_id: Requirement ID (e.g., "V5.1.1")
            findings: List of findings mapped to this requirement
            evidence: Optional additional evidence (code snippets, test results, etc.)

        Returns:
            Assessment dictionary with status, evidence, and recommendations
        """
        requirement = get_requirement_by_id(req_id, self.asvs_data)
        if not requirement:
            logger.warning(f"Requirement {req_id} not found in ASVS data")
            return {
                "requirement_id": req_id,
                "status": "NOT_FOUND",
                "findings": [],
                "evidence": evidence or {},
                "recommendation": f"Requirement {req_id} not found in ASVS data",
            }

        # Determine status
        if not findings:
            status = "PASS"
            recommendation = f"Requirement {req_id} appears to be met (no findings mapped)"
        else:
            status = "FAIL"
            recommendation = self._generate_recommendation(req_id, requirement, findings)

        assessment = {
            "requirement_id": req_id,
            "requirement_description": requirement.get("description", ""),
            "status": status,
            "findings": findings,
            "evidence": evidence or {},
            "recommendation": recommendation,
            "category": requirement.get("category", ""),
            "level": requirement.get("level", 1),
        }

        return assessment

    def _generate_recommendation(
        self, req_id: str, requirement: Dict[str, Any], findings: List[Dict]
    ) -> str:
        """Generate recommendation based on requirement and findings."""
        description = requirement.get("description", "").lower()
        req_text = requirement.get("description", "")

        # Generic recommendations based on requirement type
        if "input validation" in description or "V5.1" in req_id:
            return "Implement server-side input validation using allowlists and parameterized queries"
        elif "output encoding" in description or "V5.2" in req_id:
            return "Implement context-aware output encoding to prevent XSS attacks"
        elif "authentication" in description or "V2" in req_id:
            return "Ensure all authentication controls are enforced server-side and failures are logged"
        elif "session" in description or "V3" in req_id:
            return "Implement secure session management with proper token generation and validation"
        elif "access control" in description or "V4" in req_id:
            return "Implement proper access control checks for all authenticated requests"
        else:
            return f"Address findings related to {req_text}"

    def calculate_category_compliance(
        self, category: str, assessments: List[Dict]
    ) -> Dict[str, Any]:
        """
        Calculate compliance percentage for a category.

        Args:
            category: Category ID (e.g., "V5")
            assessments: List of requirement assessments for this category

        Returns:
            Category compliance summary
        """
        if not assessments:
            return {
                "category": category,
                "compliance": 0.0,
                "requirements_met": 0,
                "requirements_total": 0,
                "requirements_failed": 0,
                "requirements_not_tested": 0,
            }

        total = len(assessments)
        passed = sum(1 for a in assessments if a.get("status") == "PASS")
        failed = sum(1 for a in assessments if a.get("status") == "FAIL")
        not_tested = sum(1 for a in assessments if a.get("status") == "NOT_TESTED")

        compliance = (passed / total * 100) if total > 0 else 0.0

        # Get category name
        category_name = ""
        for cat_id, cat_data in self.asvs_data.get("categories", {}).items():
            if cat_id == category:
                category_name = cat_data.get("name", category)
                break

        return {
            "category": category,
            "name": category_name,
            "compliance": round(compliance, 2),
            "requirements_met": passed,
            "requirements_total": total,
            "requirements_failed": failed,
            "requirements_not_tested": not_tested,
            "requirements": assessments,
        }

    def calculate_overall_compliance(
        self, assessments: Dict[str, List[Dict]]
    ) -> Dict[str, Any]:
        """
        Calculate overall compliance score and determine achieved level.

        Args:
            assessments: Dictionary mapping category IDs to lists of assessments

        Returns:
            Overall compliance summary
        """
        all_assessments = []
        category_summaries = {}

        for category, category_assessments in assessments.items():
            category_summary = self.calculate_category_compliance(
                category, category_assessments
            )
            category_summaries[category] = category_summary
            all_assessments.extend(category_assessments)

        if not all_assessments:
            return {
                "overall_compliance": 0.0,
                "level_achieved": 0,
                "total_requirements": 0,
                "requirements_met": 0,
                "requirements_failed": 0,
                "categories": category_summaries,
            }

        total = len(all_assessments)
        passed = sum(1 for a in all_assessments if a.get("status") == "PASS")
        failed = sum(1 for a in all_assessments if a.get("status") == "FAIL")

        overall_compliance = (passed / total * 100) if total > 0 else 0.0

        # Determine achieved level based on compliance percentage
        # Level 1: >= 80%, Level 2: >= 90%, Level 3: >= 95%
        target_level = self.asvs_data.get("level", 2)
        if overall_compliance >= 95:
            level_achieved = 3
        elif overall_compliance >= 90:
            level_achieved = 2
        elif overall_compliance >= 80:
            level_achieved = 1
        else:
            level_achieved = 0

        return {
            "overall_compliance": round(overall_compliance, 2),
            "level_achieved": level_achieved,
            "target_level": target_level,
            "total_requirements": total,
            "requirements_met": passed,
            "requirements_failed": failed,
            "categories": category_summaries,
        }

    def assess_compliance(
        self, findings: List[Dict[str, Any]], out_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Assess compliance for all ASVS requirements based on findings.

        Args:
            findings: List of all findings (from web scanner, CodeQL, etc.)
            out_dir: Optional output directory for evidence storage

        Returns:
            Complete compliance assessment
        """
        logger.info(f"Assessing compliance for {len(findings)} findings")

        # Map all findings to ASVS requirements
        requirement_findings = defaultdict(list)
        requirement_mappings = {}

        for finding in findings:
            mappings = self.mapper.map_finding_to_asvs(finding)
            for mapping in mappings:
                req_id = mapping["requirement_id"]
                requirement_findings[req_id].append(finding)
                requirement_mappings[req_id] = mapping

        # Assess each requirement
        assessments_by_category = defaultdict(list)
        all_assessments = []

        for category_id, category_data in self.asvs_data.get("categories", {}).items():
            for requirement in category_data.get("requirements", []):
                req_id = requirement.get("id")
                if not req_id:
                    continue

                req_findings = requirement_findings.get(req_id, [])
                assessment = self.assess_requirement_compliance(
                    req_id, req_findings, evidence={}
                )
                assessments_by_category[category_id].append(assessment)
                all_assessments.append(assessment)

        # Calculate compliance scores
        overall = self.calculate_overall_compliance(assessments_by_category)

        return {
            "asvs_version": self.asvs_data.get("version", "5.0.0"),
            "verification_level": self.asvs_data.get("level", 2),
            "assessment_date": datetime.now().isoformat(),
            "overall_compliance": overall,
            "assessments": all_assessments,
            "assessments_by_category": dict(assessments_by_category),
        }


# Convenience functions
def assess_requirement_compliance(
    req_id: str,
    findings: List[Dict],
    asvs_data: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assess compliance for a single requirement."""
    assessor = ComplianceAssessor(asvs_data)
    return assessor.assess_requirement_compliance(req_id, findings, evidence)


def calculate_category_compliance(
    category: str, assessments: List[Dict], asvs_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculate compliance for a category."""
    assessor = ComplianceAssessor(asvs_data)
    return assessor.calculate_category_compliance(category, assessments)


def calculate_overall_compliance(
    assessments: Dict[str, List[Dict]], asvs_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculate overall compliance."""
    assessor = ComplianceAssessor(asvs_data)
    return assessor.calculate_overall_compliance(assessments)
