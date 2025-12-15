#!/usr/bin/env python3
"""
LLM-Powered ASVS Compliance Analyzer

Uses LLM for intelligent ASVS compliance assessment when rule-based mapping
is insufficient or ambiguous.
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add paths for cross-package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger

logger = get_logger()


class LLMComplianceAnalyzer:
    """Uses LLM for intelligent ASVS compliance assessment."""

    def __init__(self, llm_client):
        """
        Initialize LLM analyzer.

        Args:
            llm_client: LLM client instance (from packages.llm_analysis.llm.client)
        """
        self.llm = llm_client

    def analyze_requirement_with_llm(
        self,
        req_id: str,
        requirement: Dict[str, Any],
        code_context: Optional[str] = None,
        findings: List[Dict[str, Any]] = None,
        repo_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Use LLM to assess if ASVS requirement is met based on code and findings.

        Args:
            req_id: Requirement ID (e.g., "V5.1.1")
            requirement: Requirement dictionary with description
            code_context: Optional code context relevant to requirement
            findings: Optional list of findings related to requirement
            repo_path: Optional repository path for additional context

        Returns:
            LLM assessment with compliance status, reasoning, and recommendations
        """
        if not self.llm:
            logger.warning("LLM client not available, skipping LLM analysis")
            return {
                "requirement_id": req_id,
                "status": "NOT_ANALYZED",
                "reasoning": "LLM client not available",
            }

        logger.info(f"Analyzing requirement {req_id} with LLM")

        # Build prompt
        prompt = self._build_analysis_prompt(req_id, requirement, code_context, findings)

        try:
            # Use LLM to analyze
            response = self.llm.generate_structured(
                prompt=prompt,
                schema=self._get_analysis_schema(),
                task_type="compliance_analysis",
            )

            return {
                "requirement_id": req_id,
                "status": response.get("status", "UNKNOWN"),
                "confidence": response.get("confidence", 0.0),
                "reasoning": response.get("reasoning", ""),
                "evidence": response.get("evidence", []),
                "recommendation": response.get("recommendation", ""),
                "llm_analysis": True,
            }

        except Exception as e:
            logger.error(f"LLM analysis failed for {req_id}: {e}")
            return {
                "requirement_id": req_id,
                "status": "ANALYSIS_FAILED",
                "error": str(e),
            }

    def _build_analysis_prompt(
        self,
        req_id: str,
        requirement: Dict[str, Any],
        code_context: Optional[str],
        findings: List[Dict[str, Any]],
    ) -> str:
        """Build LLM prompt for requirement analysis."""
        req_desc = requirement.get("description", "")
        req_category = requirement.get("category", "")

        prompt = f"""You are a security compliance analyst assessing OWASP ASVS requirement compliance.

**Requirement**: {req_id}
**Category**: {req_category}
**Description**: {req_desc}

**Your Task**: Assess whether this requirement is met based on the provided code context and findings.

"""

        if code_context:
            prompt += f"""**Code Context**:
```
{code_context[:2000]}  # Limit context size
```

"""

        if findings:
            prompt += "**Related Findings**:\n"
            for finding in findings[:10]:  # Limit to first 10 findings
                finding_msg = finding.get("message", "") or finding.get("vulnerability_type", "")
                prompt += f"- {finding_msg[:200]}\n"
            prompt += "\n"

        prompt += """**Analysis Requirements**:
1. Determine if the requirement is PASS, FAIL, or NOT_APPLICABLE
2. Provide confidence level (0.0-1.0)
3. Explain your reasoning with specific evidence
4. If FAIL, provide actionable recommendations

**Response Format**:
- status: PASS, FAIL, or NOT_APPLICABLE
- confidence: float between 0.0 and 1.0
- reasoning: Detailed explanation
- evidence: List of specific evidence points
- recommendation: Actionable recommendation if FAIL
"""

        return prompt

    def _get_analysis_schema(self) -> Dict[str, Any]:
        """Get structured schema for LLM response."""
        return {
            "status": "string - PASS, FAIL, or NOT_APPLICABLE",
            "confidence": "float (0.0-1.0) - Confidence in assessment",
            "reasoning": "string - Detailed explanation of assessment",
            "evidence": "list of strings - Specific evidence points",
            "recommendation": "string - Actionable recommendation if FAIL, empty if PASS",
        }

    def enhance_mapping_with_llm(
        self, finding: Dict[str, Any], potential_requirements: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Use LLM to enhance finding-to-requirement mapping when ambiguous.

        Args:
            finding: Finding dictionary
            potential_requirements: List of potential ASVS requirement IDs

        Returns:
            List of enhanced mappings with LLM confidence scores
        """
        if not self.llm or not potential_requirements:
            return []

        logger.debug(f"Enhancing mapping for finding with LLM")

        finding_msg = finding.get("message", "") or finding.get("vulnerability_type", "")
        rule_id = finding.get("rule_id", "")

        prompt = f"""You are mapping a security finding to OWASP ASVS requirements.

**Finding**:
- Rule ID: {rule_id}
- Message: {finding_msg}
- Vulnerability Type: {finding.get('vulnerability_type', 'unknown')}

**Potential ASVS Requirements**: {', '.join(potential_requirements)}

**Your Task**: Determine which requirements are most relevant and provide confidence scores.

**Response Format**:
- mappings: List of dicts with keys: requirement_id, relevance_score (0.0-1.0), reasoning
"""

        try:
            response = self.llm.generate_structured(
                prompt=prompt,
                schema={
                    "mappings": "list of dicts with keys: requirement_id, relevance_score, reasoning"
                },
                task_type="requirement_mapping",
            )

            return response.get("mappings", [])

        except Exception as e:
            logger.error(f"LLM mapping enhancement failed: {e}")
            return []


# Convenience function
def analyze_requirement_with_llm(
    req_id: str,
    requirement: Dict[str, Any],
    llm_client,
    code_context: Optional[str] = None,
    findings: List[Dict[str, Any]] = None,
    repo_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Analyze requirement with LLM."""
    analyzer = LLMComplianceAnalyzer(llm_client)
    return analyzer.analyze_requirement_with_llm(
        req_id, requirement, code_context, findings, repo_path
    )
