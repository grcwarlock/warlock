"""Quantum readiness assessment.

Scans findings and configuration data for cryptographic algorithm usage
and flags algorithms vulnerable to quantum computing attacks (Shor's
algorithm for asymmetric, Grover's for symmetric).

Recommends NIST-approved post-quantum cryptography (PQC) replacements
per FIPS 203/204/205 (2024).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from warlock.db.models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cryptographic algorithm classification
# ---------------------------------------------------------------------------


@dataclass
class CryptoAlgorithm:
    """Classification of a cryptographic algorithm."""

    name: str
    category: str  # "asymmetric", "symmetric", "hash", "kex", "signature"
    quantum_risk: str  # "broken", "weakened", "safe", "pqc"
    key_size: int = 0
    description: str = ""
    pqc_replacement: str = ""


# Algorithms broken by Shor's algorithm (polynomial-time factoring/DLOG)
_QUANTUM_BROKEN: dict[str, CryptoAlgorithm] = {
    "rsa": CryptoAlgorithm(
        name="RSA",
        category="asymmetric",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- factoring RSA modulus in polynomial time",
        pqc_replacement="ML-KEM (FIPS 203) for encryption, ML-DSA (FIPS 204) for signatures",
    ),
    "ecdsa": CryptoAlgorithm(
        name="ECDSA",
        category="signature",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- ECDLP solved in polynomial time",
        pqc_replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    ),
    "ecdh": CryptoAlgorithm(
        name="ECDH",
        category="kex",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- ECDLP solved in polynomial time",
        pqc_replacement="ML-KEM (FIPS 203)",
    ),
    "dsa": CryptoAlgorithm(
        name="DSA",
        category="signature",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- DLP solved in polynomial time",
        pqc_replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    ),
    "dh": CryptoAlgorithm(
        name="Diffie-Hellman",
        category="kex",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- DLP solved in polynomial time",
        pqc_replacement="ML-KEM (FIPS 203)",
    ),
    "ed25519": CryptoAlgorithm(
        name="Ed25519",
        category="signature",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- curve25519 ECDLP",
        pqc_replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    ),
    "ed448": CryptoAlgorithm(
        name="Ed448",
        category="signature",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- curve448 ECDLP",
        pqc_replacement="ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)",
    ),
    "x25519": CryptoAlgorithm(
        name="X25519",
        category="kex",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- curve25519 ECDLP",
        pqc_replacement="ML-KEM (FIPS 203) or X25519Kyber768",
    ),
    "elgamal": CryptoAlgorithm(
        name="ElGamal",
        category="asymmetric",
        quantum_risk="broken",
        description="Broken by Shor's algorithm -- DLP",
        pqc_replacement="ML-KEM (FIPS 203)",
    ),
}

# Algorithms weakened by Grover's algorithm (quadratic speedup on search)
_QUANTUM_WEAKENED: dict[str, CryptoAlgorithm] = {
    "aes-128": CryptoAlgorithm(
        name="AES-128",
        category="symmetric",
        quantum_risk="weakened",
        key_size=128,
        description="Grover's reduces effective security to 64-bit -- upgrade to AES-256",
        pqc_replacement="AES-256",
    ),
    "3des": CryptoAlgorithm(
        name="3DES",
        category="symmetric",
        quantum_risk="weakened",
        key_size=112,
        description="Already deprecated; Grover's reduces to ~56-bit effective security",
        pqc_replacement="AES-256",
    ),
    "sha-1": CryptoAlgorithm(
        name="SHA-1",
        category="hash",
        quantum_risk="weakened",
        description="Already broken classically; Grover's further weakens collision resistance",
        pqc_replacement="SHA-256 or SHA-3",
    ),
}

# PQC-safe algorithms (NIST FIPS 203/204/205, approved 2024)
_PQC_ALGORITHMS: dict[str, CryptoAlgorithm] = {
    "ml-kem": CryptoAlgorithm(
        name="ML-KEM (Kyber)",
        category="kex",
        quantum_risk="pqc",
        description="FIPS 203 -- Module-Lattice-Based Key-Encapsulation Mechanism",
    ),
    "ml-dsa": CryptoAlgorithm(
        name="ML-DSA (Dilithium)",
        category="signature",
        quantum_risk="pqc",
        description="FIPS 204 -- Module-Lattice-Based Digital Signature Algorithm",
    ),
    "slh-dsa": CryptoAlgorithm(
        name="SLH-DSA (SPHINCS+)",
        category="signature",
        quantum_risk="pqc",
        description="FIPS 205 -- Stateless Hash-Based Digital Signature Algorithm",
    ),
    "aes-256": CryptoAlgorithm(
        name="AES-256",
        category="symmetric",
        quantum_risk="safe",
        key_size=256,
        description="128-bit effective security under Grover's -- considered quantum safe",
    ),
    "sha-256": CryptoAlgorithm(
        name="SHA-256",
        category="hash",
        quantum_risk="safe",
        description="128-bit effective collision resistance under Grover's",
    ),
    "sha-3": CryptoAlgorithm(
        name="SHA-3",
        category="hash",
        quantum_risk="safe",
        description="128-bit effective collision resistance under Grover's",
    ),
}

# Regex patterns to detect crypto algorithms in finding data
_CRYPTO_PATTERNS: list[tuple[str, str]] = [
    (r"\brsa\b", "rsa"),
    (r"\becdsa\b", "ecdsa"),
    (r"\becdh\b", "ecdh"),
    (r"\bedh\b", "dh"),
    (r"\bdiffie.?hellman\b", "dh"),
    (r"\b(?:dsa)\b(?!.*ml-dsa)", "dsa"),
    (r"\bed25519\b", "ed25519"),
    (r"\bed448\b", "ed448"),
    (r"\bx25519\b", "x25519"),
    (r"\belgamal\b", "elgamal"),
    (r"\baes.?128\b", "aes-128"),
    (r"\b3des\b|\btriple.?des\b", "3des"),
    (r"\bsha.?1\b", "sha-1"),
    (r"\bml.?kem\b|\bkyber\b", "ml-kem"),
    (r"\bml.?dsa\b|\bdilithium\b", "ml-dsa"),
    (r"\bslh.?dsa\b|\bsphincs\b", "slh-dsa"),
]


@dataclass
class QuantumFinding:
    """A finding of quantum-vulnerable cryptography."""

    finding_id: str
    resource: str
    algorithm: str
    algorithm_info: CryptoAlgorithm
    source: str = ""
    context: str = ""


@dataclass
class QuantumReadinessReport:
    """Summary of quantum readiness assessment."""

    total_findings_scanned: int = 0
    crypto_findings: int = 0
    quantum_broken_count: int = 0
    quantum_weakened_count: int = 0
    pqc_ready_count: int = 0
    safe_count: int = 0
    broken_algorithms: list[QuantumFinding] = field(default_factory=list)
    weakened_algorithms: list[QuantumFinding] = field(default_factory=list)
    pqc_detected: list[QuantumFinding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    readiness_score: float = 0.0  # 0-100, higher = more quantum ready


def _scan_text_for_crypto(text: str) -> list[tuple[str, str]]:
    """Scan text for cryptographic algorithm mentions.

    Returns list of (algorithm_key, matched_text) tuples.
    """
    found: list[tuple[str, str]] = []
    text_lower = text.lower()
    for pattern, algo_key in _CRYPTO_PATTERNS:
        matches = re.findall(pattern, text_lower)
        for m in matches:
            found.append((algo_key, m))
    return found


def assess_quantum_readiness(session: Session) -> QuantumReadinessReport:
    """Scan all findings for cryptographic algorithm usage and assess quantum readiness.

    Examines finding titles, descriptions, and raw data for mentions of
    cryptographic algorithms, then classifies each as broken, weakened,
    safe, or PQC-ready under quantum computing threats.
    """
    report = QuantumReadinessReport()

    findings = session.query(Finding).all()
    report.total_findings_scanned = len(findings)

    seen_combos: set[tuple[str, str]] = set()  # (finding_id, algo_key)

    for finding in findings:
        # Build text corpus from finding fields
        parts = [
            finding.title or "",
            finding.description or "",
            finding.resource_id or "",
            finding.event_type or "",
        ]
        if finding.raw_data and isinstance(finding.raw_data, dict):
            parts.append(str(finding.raw_data))

        text = " ".join(parts)
        detected = _scan_text_for_crypto(text)

        for algo_key, matched in detected:
            combo = (finding.id, algo_key)
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            if algo_key in _QUANTUM_BROKEN:
                algo_info = _QUANTUM_BROKEN[algo_key]
                qf = QuantumFinding(
                    finding_id=finding.id,
                    resource=finding.resource_id or "",
                    algorithm=algo_info.name,
                    algorithm_info=algo_info,
                    source=finding.source or "",
                    context=matched,
                )
                report.broken_algorithms.append(qf)
                report.quantum_broken_count += 1
            elif algo_key in _QUANTUM_WEAKENED:
                algo_info = _QUANTUM_WEAKENED[algo_key]
                qf = QuantumFinding(
                    finding_id=finding.id,
                    resource=finding.resource_id or "",
                    algorithm=algo_info.name,
                    algorithm_info=algo_info,
                    source=finding.source or "",
                    context=matched,
                )
                report.weakened_algorithms.append(qf)
                report.quantum_weakened_count += 1
            elif algo_key in _PQC_ALGORITHMS:
                algo_info = _PQC_ALGORITHMS[algo_key]
                qf = QuantumFinding(
                    finding_id=finding.id,
                    resource=finding.resource_id or "",
                    algorithm=algo_info.name,
                    algorithm_info=algo_info,
                    source=finding.source or "",
                    context=matched,
                )
                report.pqc_detected.append(qf)
                report.pqc_ready_count += 1

    report.crypto_findings = (
        report.quantum_broken_count + report.quantum_weakened_count + report.pqc_ready_count
    )

    # Compute readiness score
    if report.crypto_findings > 0:
        safe_weight = report.pqc_ready_count + report.safe_count
        total = report.crypto_findings
        report.readiness_score = round(safe_weight / total * 100, 1)
    else:
        report.readiness_score = 100.0  # No crypto found = nothing to fix

    # Generate recommendations
    if report.quantum_broken_count > 0:
        broken_names = sorted({qf.algorithm for qf in report.broken_algorithms})
        report.recommendations.append(
            f"CRITICAL: {report.quantum_broken_count} uses of quantum-broken algorithms "
            f"detected ({', '.join(broken_names)}). Begin PQC migration planning."
        )
        report.recommendations.append(
            "Prioritize replacing RSA/ECDSA key exchange and signatures with "
            "ML-KEM (FIPS 203) and ML-DSA (FIPS 204)."
        )
    if report.quantum_weakened_count > 0:
        weak_names = sorted({qf.algorithm for qf in report.weakened_algorithms})
        report.recommendations.append(
            f"WARNING: {report.quantum_weakened_count} uses of quantum-weakened algorithms "
            f"detected ({', '.join(weak_names)}). Plan upgrades to 256-bit variants."
        )
    if report.pqc_ready_count > 0:
        report.recommendations.append(
            f"POSITIVE: {report.pqc_ready_count} instances of PQC or quantum-safe "
            f"algorithms detected."
        )
    if report.quantum_broken_count == 0 and report.quantum_weakened_count == 0:
        report.recommendations.append(
            "No quantum-vulnerable algorithms detected in current findings. "
            "Continue monitoring as new findings are ingested."
        )

    report.recommendations.append(
        "Reference: NIST PQC standards -- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), "
        "FIPS 205 (SLH-DSA). Target migration completion before 2030."
    )

    return report
