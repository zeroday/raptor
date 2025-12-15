#!/usr/bin/env python3
"""
ASVS Mapper

Maps RAPTOR findings to OWASP ASVS requirements using:
- Rule-based mappings (SQLi → V5.x.x, XSS → V7.x.x)
- CWE-based mappings
- LLM-assisted mappings (for complex cases)
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add paths for cross-package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger
from packages.compliance.asvs_loader import load_asvs_requirements, get_requirements_by_category

logger = get_logger()


# Rule-based mappings: vulnerability type → ASVS category/requirements
VULN_TO_ASVS_MAPPINGS = {
    # SQL Injection
    "sqli": ["V5.1.1", "V5.1.2", "V5.1.3", "V5.2.1"],  # Data Validation
    "sql-injection": ["V5.1.1", "V5.1.2", "V5.1.3", "V5.2.1"],
    "sql_injection": ["V5.1.1", "V5.1.2", "V5.1.3", "V5.2.1"],
    
    # XSS (Cross-Site Scripting)
    "xss": ["V5.2.1", "V5.2.2", "V7.1.1", "V7.1.2"],  # Data Validation + Output Encoding
    "cross-site-scripting": ["V5.2.1", "V5.2.2", "V7.1.1", "V7.1.2"],
    "cross_site_scripting": ["V5.2.1", "V5.2.2", "V7.1.1", "V7.1.2"],
    
    # Command Injection
    "command-injection": ["V5.1.1", "V5.1.2", "V5.1.3"],  # Data Validation
    "command_injection": ["V5.1.1", "V5.1.2", "V5.1.3"],
    "os-command-injection": ["V5.1.1", "V5.1.2", "V5.1.3"],
    
    # Path Traversal
    "path-traversal": ["V5.1.1", "V5.1.2", "V11.1.1", "V11.1.2"],  # Data Validation + Files
    "path_traversal": ["V5.1.1", "V5.1.2", "V11.1.1", "V11.1.2"],
    "directory-traversal": ["V5.1.1", "V5.1.2", "V11.1.1", "V11.1.2"],
    
    # Authentication Issues
    "auth-bypass": ["V2.1.1", "V2.1.2", "V2.1.3"],  # Authentication
    "authentication-bypass": ["V2.1.1", "V2.1.2", "V2.1.3"],
    "weak-authentication": ["V2.1.1", "V2.2.1", "V2.2.2"],
    
    # Session Management
    "session-fixation": ["V3.1.1", "V3.1.2", "V3.1.3"],  # Session Management
    "session-hijacking": ["V3.1.1", "V3.1.2", "V3.2.1"],
    "weak-session": ["V3.1.1", "V3.2.1", "V3.2.2"],
    
    # CSRF
    "csrf": ["V4.1.1", "V4.1.2"],  # Access Control
    "cross-site-request-forgery": ["V4.1.1", "V4.1.2"],
    
    # SSRF
    "ssrf": ["V5.1.1", "V5.1.2", "V12.1.1"],  # Data Validation + API Security
    "server-side-request-forgery": ["V5.1.1", "V5.1.2", "V12.1.1"],
    
    # XXE
    "xxe": ["V5.1.1", "V5.1.2", "V12.1.1"],  # Data Validation + API Security
    "xml-external-entity": ["V5.1.1", "V5.1.2", "V12.1.1"],
    
    # Insecure Deserialization
    "deserialization": ["V5.1.1", "V5.1.2", "V8.1.1"],  # Data Validation + Malicious Code
    "insecure-deserialization": ["V5.1.1", "V5.1.2", "V8.1.1"],
    
    # Cryptographic Issues
    "weak-crypto": ["V6.1.1", "V6.1.2", "V6.2.1"],  # Cryptography
    "weak-encryption": ["V6.1.1", "V6.1.2", "V6.2.1"],
    "insecure-random": ["V6.1.1", "V6.2.1"],
}

# CWE to ASVS mappings
CWE_TO_ASVS_MAPPINGS = {
    "CWE-89": ["V5.1.1", "V5.1.2", "V5.1.3"],  # SQL Injection
    "CWE-79": ["V5.2.1", "V5.2.2", "V7.1.1"],  # XSS
    "CWE-78": ["V5.1.1", "V5.1.2", "V5.1.3"],  # OS Command Injection
    "CWE-22": ["V5.1.1", "V5.1.2", "V11.1.1"],  # Path Traversal
    "CWE-287": ["V2.1.1", "V2.1.2"],  # Improper Authentication
    "CWE-352": ["V4.1.1", "V4.1.2"],  # CSRF
    "CWE-918": ["V5.1.1", "V5.1.2", "V12.1.1"],  # SSRF
    "CWE-611": ["V5.1.1", "V5.1.2", "V12.1.1"],  # XXE
    "CWE-502": ["V5.1.1", "V5.1.2", "V8.1.1"],  # Deserialization
    "CWE-327": ["V6.1.1", "V6.1.2"],  # Weak Crypto
    "CWE-330": ["V6.1.1", "V6.2.1"],  # Weak Random
}


class ASVSMapper:
    """Maps RAPTOR findings to ASVS requirements."""

    def __init__(self, asvs_data: Optional[Dict[str, Any]] = None):
        """
        Initialize mapper with ASVS data.

        Args:
            asvs_data: Pre-loaded ASVS requirements. If None, loads default.
        """
        self.asvs_data = asvs_data or load_asvs_requirements("5.0.0", 2)

    def map_finding_to_asvs(
        self, finding: Dict[str, Any], asvs_requirements: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Map a single finding to relevant ASVS requirements.

        Args:
            finding: Finding dictionary (from SARIF, web scanner, etc.)
            asvs_requirements: Optional ASVS data (uses instance data if None)

        Returns:
            List of mappings, each containing requirement ID and context
        """
        if asvs_requirements is None:
            asvs_requirements = self.asvs_data

        mappings = []

        # Try rule-based mapping first
        rule_id = finding.get("rule_id", "").lower()
        vuln_type = finding.get("vulnerability_type", "").lower()
        message = finding.get("message", "").lower()

        # Extract vulnerability type from various fields
        detected_type = self._detect_vulnerability_type(finding)

        # Map based on vulnerability type
        if detected_type:
            req_ids = VULN_TO_ASVS_MAPPINGS.get(detected_type, [])
            for req_id in req_ids:
                mappings.append({
                    "requirement_id": req_id,
                    "mapping_method": "rule-based",
                    "vulnerability_type": detected_type,
                    "finding": finding,
                })

        # Try CWE-based mapping
        cwe = finding.get("cwe")
        if cwe:
            cwe_mappings = CWE_TO_ASVS_MAPPINGS.get(cwe.upper(), [])
            for req_id in cwe_mappings:
                # Avoid duplicates
                if not any(m.get("requirement_id") == req_id for m in mappings):
                    mappings.append({
                        "requirement_id": req_id,
                        "mapping_method": "cwe-based",
                        "cwe": cwe,
                        "finding": finding,
                    })

        # If no mappings found, try to infer from message/rule_id
        if not mappings:
            inferred = self._infer_from_context(finding)
            if inferred:
                mappings.extend(inferred)

        return mappings

    def _detect_vulnerability_type(self, finding: Dict[str, Any]) -> Optional[str]:
        """Detect vulnerability type from finding fields."""
        # Check explicit vulnerability_type field
        vuln_type = finding.get("vulnerability_type", "").lower()
        if vuln_type and vuln_type in VULN_TO_ASVS_MAPPINGS:
            return vuln_type

        # Check rule_id
        rule_id = finding.get("rule_id", "").lower()
        for vuln_key in VULN_TO_ASVS_MAPPINGS.keys():
            if vuln_key in rule_id:
                return vuln_key

        # Check message
        message = finding.get("message", "").lower()
        for vuln_key in VULN_TO_ASVS_MAPPINGS.keys():
            if vuln_key.replace("-", " ") in message or vuln_key.replace("_", " ") in message:
                return vuln_key

        return None

    def _infer_from_context(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Infer ASVS requirements from finding context when no direct mapping exists."""
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()

        mappings = []

        # Generic input validation issues
        if any(keyword in message for keyword in ["input", "user input", "parameter", "validation"]):
            mappings.append({
                "requirement_id": "V5.1.1",
                "mapping_method": "context-inference",
                "finding": finding,
            })

        # Generic output encoding issues
        if any(keyword in message for keyword in ["output", "encoding", "encode", "escape"]):
            mappings.append({
                "requirement_id": "V5.2.1",
                "mapping_method": "context-inference",
                "finding": finding,
            })

        return mappings

    def map_web_finding_to_asvs(self, web_finding: Dict[str, Any]) -> List[str]:
        """
        Map web scanner findings to ASVS requirements.

        Args:
            web_finding: Web scanner finding (from packages/web/fuzzer.py)

        Returns:
            List of ASVS requirement IDs
        """
        mappings = self.map_finding_to_asvs(web_finding)
        return [m["requirement_id"] for m in mappings]

    def map_codeql_finding_to_asvs(self, codeql_finding: Dict[str, Any]) -> List[str]:
        """
        Map CodeQL findings to ASVS requirements using CWE tags.

        Args:
            codeql_finding: CodeQL finding (from packages/codeql/)

        Returns:
            List of ASVS requirement IDs
        """
        mappings = self.map_finding_to_asvs(codeql_finding)
        return [m["requirement_id"] for m in mappings]

    def map_fuzzing_result_to_asvs(self, fuzzing_result: Dict[str, Any]) -> List[str]:
        """
        Map fuzzing results to ASVS categories.

        Args:
            fuzzing_result: Fuzzing result (from packages/fuzzing/)

        Returns:
            List of ASVS requirement IDs
        """
        # Fuzzing results typically indicate input validation issues
        # Map to Data Validation category
        mappings = self.map_finding_to_asvs(fuzzing_result)
        
        # If no specific mapping, default to general input validation
        if not mappings:
            return ["V5.1.1", "V5.1.2"]
        
        return [m["requirement_id"] for m in mappings]


# Convenience functions
def map_finding_to_asvs(
    finding: Dict[str, Any], asvs_requirements: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Map a finding to ASVS requirements."""
    mapper = ASVSMapper(asvs_requirements)
    return mapper.map_finding_to_asvs(finding, asvs_requirements)


def map_web_finding_to_asvs(web_finding: Dict[str, Any]) -> List[str]:
    """Map web finding to ASVS requirements."""
    mapper = ASVSMapper()
    return mapper.map_web_finding_to_asvs(web_finding)


def map_codeql_finding_to_asvs(codeql_finding: Dict[str, Any]) -> List[str]:
    """Map CodeQL finding to ASVS requirements."""
    mapper = ASVSMapper()
    return mapper.map_codeql_finding_to_asvs(codeql_finding)


def map_fuzzing_result_to_asvs(fuzzing_result: Dict[str, Any]) -> List[str]:
    """Map fuzzing result to ASVS requirements."""
    mapper = ASVSMapper()
    return mapper.map_fuzzing_result_to_asvs(fuzzing_result)
