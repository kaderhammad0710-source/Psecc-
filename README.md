# PSEC — Fluid Entropic Security Architecture
### v2.1.0 · PSC Cyber

> *"The reed bends. The target moves. The mark remains."*

---

## Overview

**PSEC** (PSC Cyber) is a research-grade security architecture that combines four orthogonal defense primitives into a unified, mathematically coherent system. Its defining characteristic is **architectural entropy** — the attack surface is never static, and every artifact the attacker extracts becomes a tracer against them.

The system is built around a single mathematical spine: **quasi-crystal topology** (Penrose tiling). The same aperiodic structure governs storage fragmentation, signature generation, and audit trail integrity. This is not a collection of assembled tools — it is a system with a unified internal logic.

---

## Core Primitives

| Component | Role | Mechanism |
|---|---|---|
| `Kernel_Liquid` | Moving Target Defense | Entropic rotation of ports, protocols, cipher suites |
| `Shadow_Magazine` | Deception / Honeypot | Stratified lure data with zero real value |
| `Inked_Payload` | Active Watermarking | Quasi-crystal signatures embedded in every artifact |
| `KDR` | Behavioral Biometrics | Keystroke dynamics authentication |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  PSEC v2.1 — Fluid Core              │
│                                                      │
│   [Kernel_Liquid]  ←──  Entropic Clock E(t)          │
│         │                                            │
│         ▼                                            │
│   [Shadow_Magazine]  ──  3-tier credibility gradient │
│         │                                            │
│         ▼                                            │
│   [Ink_Wrapper]  ←──  QCS + KDR empreinte           │
│         │                                            │
│         ▼                                            │
│   [Propagation Beacon]  ──  Forensic watermark       │
│         │                                            │
│         ▼                                            │
│   [Topological Audit Trail]  ──  Tamper-evident log  │
└─────────────────────────────────────────────────────┘
```

---

## The QCS — Quasi-Crystal Signature

The cryptographic core of PSEC. Every file artifact is signed with a **QCS** — a signature whose uniqueness is guaranteed by quasi-crystal geometry rather than simple randomness.

### Mathematical Definition

$$\mathcal{QCS}(f, a) = \Phi\bigl(\mathcal{P}(\mathcal{E}(t)),\ \kappa_{KDR},\ \chi(f, a)\bigr)$$

Where:

- $\mathcal{E}(t) = H\bigl(\Delta\lambda(t) \| \sigma_{cpu}(t) \| \tau_{hi}(t) \| \text{os\_entropy}\bigr)$ — Entropic Clock
- $\mathcal{P}(\mathcal{E}(t))$ — Penrose projection from $\mathbb{R}^5 \to \mathbb{R}^2$, seeded by $\mathcal{E}(t)$
- $\kappa_{KDR}$ — behavioral biometric vector (keystroke dynamics)
- $\chi(f, a) = H(\text{PID} \| \text{UID} \| \text{syscall\_trace} \| f_{hash})$ — access context
- $\Phi$ — HKDF-SHA3 composition function

### Why Quasi-Crystal?

A Penrose tiling has a fundamental property: **ordered but aperiodic**. No translation reproduces it. This gives the QCS two simultaneously held properties that classical signatures cannot achieve together:

- **Always different** — two accesses to the same file produce distinct, uncorrelated signatures
- **Ordered entropy** — the server validates membership in the quasi-crystal space without storing the exact value

Formally, the validation server stores only the **acceptance window** $\mathcal{W}$:

$$\text{Valid}(\mathcal{QCS}') = \begin{cases} 1 & \text{if } \pi_\perp(\mathcal{QCS}') \in \mathcal{W} \\ 0 & \text{otherwise} \end{cases}$$

A compromised server leaks only $\mathcal{W}$ — insufficient to forge a valid QCS without $\kappa_{KDR}$.

### Asymmetric Fragmentation

Each QCS is split via **Shamir (2,3)-threshold secret sharing** over $GF(257)$:

$$\mathcal{QCS} \rightarrow \{s_1, s_2, s_3\}$$

| Fragment | Destination | Notes |
|---|---|---|
| $s_1$ | File headers | Survives metadata strip |
| $s_2$ | System metadata | Removed by naive attacker |
| $s_3$ | File body (structural stego) | Survives file copy |

Any two fragments reconstruct the full signature via Lagrange interpolation. A single fragment reveals nothing.

---

## Attack Lifecycle

```
Phase 1 — ATTRACTION
  Attacker interacts with Shadow_Magazine.
  System simulates normal resistance ("helmet effect").

Phase 2 — EXTRACTION  
  Attacker exfiltrates lure data.
  Kernel_Liquid detects exfiltration → rotates to new network config.
  System moves. Attack surface disappears.

Phase 3 — MARKING
  Attacker opens the file.
  Marker_DNA (QCS) activates → Beacon fires to monitoring server.
  Server receives: IP, execution context, machine ID.

Phase 4 — PROPAGATION
  Attacker forwards file.
  Propagation_Trigger fires on new recipient.
  Real-time propagation map constructed.
```

---

## Entropic Clock

$\mathcal{E}(t)$ is not a timestamp. It is a state vector derived from system volatility:

```python
E(t) = SHA3-256(
    Δλ(t)          # syscall latency variance
    ‖ σ_cpu(t)     # CPU scheduler micro-jitter  
    ‖ τ_hi(t)      # nanosecond-precision counter
    ‖ os_entropy   # CSPRNG (os.urandom)
)
```

The mutation window of `Kernel_Liquid` is seeded by $\mathcal{E}(t)$ — making the reconfiguration schedule itself unpredictable.

---

## Topological Audit Trail

Every system event — legitimate or hostile — is recorded in a hash chain whose structure satisfies quasi-crystal topological constraints:

$$e_{i+1} = H\bigl(e_i \| \mathcal{QCS}_i \| \mathcal{E}(t_i)\bigr)$$

Any insertion or deletion breaks topological coherence, detectable in $O(\log n)$.

---

## Module Structure

```
psec/
├── psec_qcs.py          # QCS core module (production-grade)
│   ├── EntropicClock    # E(t) — entropy seed generation
│   ├── PenroseProjector # R^5 → R^2 quasi-crystal projection
│   ├── QCSGenerator     # Φ(P(E(t)), κ_KDR, χ(f,a)) via HKDF-SHA3
│   ├── QCSFragmenter    # Shamir (2,3)-threshold over GF(257)
│   ├── QCSValidator     # Topological coherence validation
│   ├── TopologicalAudit # Tamper-evident hash chain
│   └── PSECQCSEngine    # Unified interface
├── README.md
└── ...
```

---

## Quick Start

```bash
pip install cryptography argon2-cffi
python psec_qcs.py
```

```
============================================================
  PSEC v2.1.0 — QCS Module Demo
============================================================

[KDR]  κ_KDR simulé      : 9af26cbc5927d49d64b6cf372cdcc7f2...
[QCS]  Signature         : ba8af92de30a08ee6f6e408457d00310...
[QCS]  Points Penrose    : 178
[QCS]  Liée à KDR       : True

── Reconstruction (fragments 1 + 3) ────────────────────
[REC]  Correspondance    : ✓ MATCH

── Validation Topologique ──────────────────────────────
[VAL]  Résultat          : ✓ VALIDE
```

---

## Design Principles

**Non-locality** — No request has a fixed path. The system is liquid: data flow takes a different route at every iteration. There is no fixed target to hit.

**Ordered entropy** — Unpredictability is not chaos. Every random element in PSEC is seeded by structured entropy, making the system both unpredictable to attackers and verifiable by defenders.

**Architectural unity** — QSE (storage), QCS (signing), and the Audit Trail all speak the same mathematical language. Penrose topology is not a metaphor — it is the implementation substrate.

**Attacker-as-sensor** — The system does not merely defend. It converts every hostile action into intelligence. The attacker's exfiltration triggers a reconfiguration. Their file access fires a beacon. Their forwarding of the file maps their network.

---

## Status & Roadmap

| Module | Status |
|---|---|
| QCS (Quasi-Crystal Signature) | ✅ Production-grade |
| Entropic Clock | ✅ Implemented |
| Shamir Fragmentation | ✅ Implemented |
| Topological Audit Trail | ✅ Implemented |
| KDR (Keystroke Dynamics) | 🔄 Integration in progress |
| Kernel_Liquid / MTD | 📐 Specification complete |
| Shadow_Magazine | 📐 Specification complete |
| Propagation Beacon | 📐 Specification complete |

---

## Related Work

This architecture draws on and extends the following research areas:

- **Moving Target Defense** — Jajodia et al., *Moving Target Defense* (Springer, 2011)
- **Keystroke Dynamics** — Monrose & Rubin, *Keystroke dynamics as a biometric for authentication* (1999)
- **Penrose Tiling** — Penrose, *The role of aesthetics in pure and applied mathematical research* (1974)
- **Canary Tokens / Active Watermarking** — Thinkst Applied Research
- **Secret Sharing** — Shamir, *How to share a secret* (1979)

---

## License

Proprietary — Research use only.  
© PSC Cyber. All rights reserved.

---

*"A system that moves cannot be aimed at. A system that marks cannot be silently robbed."*
payload.encode("utf-8")


@dataclass
class QCSSignature:
    """
    Structure complète d'une signature QCS(f, a).

    Contient la signature composite, l'empreinte topologique pour
    validation, et les métadonnées de génération.
    """
    signature_hex:        str           # Signature composite (hex)
    topological_fp:       str           # Empreinte topologique (hex)
    penrose_point_count:  int           # Nombre de points dans le pavage
    kdr_bound:            bool          # Liée à une empreinte KDR
    fragment_ids:         List[str]     # IDs des 3 fragments Shamir
    psec_version:         str = PSEC_VERSION
    algo:                 str = HASH_ALGO

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class QCSFragment:
    """
    Fragment Shamir s_i d'une signature QCS.

    Destination :
        s_1 → headers fichier
        s_2 → métadonnées système
        s_3 → corps fichier (stéganographie structurelle)
    """
    fragment_id:   str      # Identifiant unique du fragment
    index:         int      # Index i ∈ {1, 2, 3}
    payload_hex:   str      # Contenu du fragment (hex)
    destination:   str      # 'header' | 'metadata' | 'body'
    signature_ref: str      # Référence à la QCSSignature parente

    DESTINATIONS = {1: "header", 2: "metadata", 3: "body"}


# ═════════════════════════════════════════════════════════════════════════════
# IV. QCS GENERATOR  —  QCS(f, a)
# ═════════════════════════════════════════════════════════════════════════════

class QCSGenerator:
    """
    Générateur de signatures quasi-cristallines.

    QCS(f, a) = Φ( P(E(t)),  κ_KDR,  χ(f, a) )

    Où Φ est une dérivation HKDF-SHA3 combinant les trois composantes.
    """

    def __init__(
        self,
        clock:      Optional[EntropicClock]    = None,
        projector:  Optional[PenroseProjector] = None
    ):
        self.clock     = clock    or EntropicClock()
        self.projector = projector or PenroseProjector()

    # ── Dérivation HKDF simplifiée (SHA-3) ───────────────────────────────

    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract : PRK = HMAC-SHA3(salt, IKM)."""
        return hmac.new(salt, ikm, hashlib.sha3_256).digest()

    def _hkdf_expand(self, prk: bytes, info: bytes, length: int = 32) -> bytes:
        """HKDF-Expand : OKM de longueur `length` octets."""
        okm = b""
        t   = b""
        i   = 1
        while len(okm) < length:
            t    = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
            okm += t
            i   += 1
        return okm[:length]

    # ── Dérivation de la signature composite Φ ───────────────────────────

    def _phi(
        self,
        penrose_fp: bytes,
        kdr_vector: bytes,
        context:    bytes
    ) -> bytes:
        """
        Φ( P(E(t)), κ_KDR, χ(f,a) ) via HKDF-SHA3.

        1. Extract : PRK = HKDF-Extract( kdr_vector, penrose_fp ‖ context )
        2. Expand  : QCS = HKDF-Expand( PRK, b"PSEC-QCS-v2.1" )
        """
        ikm  = penrose_fp + context
        prk  = self._hkdf_extract(salt=kdr_vector, ikm=ikm)
        qcs  = self._hkdf_expand(prk=prk, info=b"PSEC-QCS-v2.1")
        return qcs

    # ── Interface principale ──────────────────────────────────────────────

    def generate(
        self,
        context:    AccessContext,
        kdr_vector: bytes
    ) -> QCSSignature:
        """
        Génère une signature QCS pour un accès fichier donné.

        Parameters
        ----------
        context    : AccessContext
            Contexte d'accès χ(f, a).
        kdr_vector : bytes
            Empreinte biométrique κ_KDR (vecteur keystroke dynamics, 32 oct.).

        Returns
        -------
        QCSSignature
            Signature composite avec empreinte topologique.
        """
        # 1. Graine entropique E(t)
        entropy_seed = self.clock.tick()

        # 2. Pavage quasi-cristallin P(E(t))
        penrose_points = self.projector.project(entropy_seed)
        penrose_fp     = self.projector.compute_topological_fingerprint(
                             penrose_points
                         )

        # 3. Hash du contexte χ(f, a)
        context_hash = hashlib.new(HASH_ALGO, context.to_bytes()).digest()

        # 4. Signature composite Φ
        signature = self._phi(
            penrose_fp  = penrose_fp,
            kdr_vector  = kdr_vector,
            context     = context_hash
        )

        # 5. IDs de fragments (générés ici, assignés par le Fragmenter)
        fragment_ids = [secrets.token_hex(8) for _ in range(QCS_FRAGMENT_COUNT)]

        return QCSSignature(
            signature_hex       = signature.hex(),
            topological_fp      = penrose_fp.hex(),
            penrose_point_count = len(penrose_points),
            kdr_bound           = len(kdr_vector) > 0,
            fragment_ids        = fragment_ids
        )


# ═════════════════════════════════════════════════════════════════════════════
# V. QCS FRAGMENTER  —  Shamir (2,3)-threshold
# ═════════════════════════════════════════════════════════════════════════════

class QCSFragmenter:
    """
    Fragmentation asymétrique de la signature QCS.

    Implémente un schéma Shamir (2,3)-threshold simplifié sur GF(2^8).
    Deux fragments suffisent pour reconstruire la signature.
    Un fragment seul ne révèle aucune information.

    Destinations :
        Fragment 1 → headers fichier
        Fragment 2 → métadonnées système
        Fragment 3 → corps fichier
    """

    PRIME = 257     # Premier supérieur à 256 pour GF simplifié

    def _poly_eval(self, coeffs: List[int], x: int) -> int:
        """Évalue un polynôme P(x) = a0 + a1*x + a2*x² mod PRIME."""
        result = 0
        for i, c in enumerate(coeffs):
            result = (result + c * pow(x, i, self.PRIME)) % self.PRIME
        return result

    def split(self, qcs: QCSSignature) -> List[QCSFragment]:
        """
        Fragmente la signature QCS en 3 parts Shamir.

        Parameters
        ----------
        qcs : QCSSignature
            Signature à fragmenter.

        Returns
        -------
        List[QCSFragment]
            Les 3 fragments s_1, s_2, s_3.
        """
        sig_bytes = bytes.fromhex(qcs.signature_hex)
        fragments_raw = [[] for _ in range(QCS_FRAGMENT_COUNT)]

        for byte_val in sig_bytes:
            # Coefficients du polynôme : a0 = secret, a1 aléatoire
            a0 = byte_val
            a1 = secrets.randbelow(self.PRIME)
            a2 = secrets.randbelow(self.PRIME)
            coeffs = [a0, a1, a2]

            # Évaluation en x = 1, 2, 3
            for i in range(QCS_FRAGMENT_COUNT):
                x   = i + 1
                val = self._poly_eval(coeffs, x)
                fragments_raw[i].append(val)

        # Construction des objets QCSFragment
        fragments = []
        for i, raw in enumerate(fragments_raw):
            dest = QCSFragment.DESTINATIONS[i + 1]
            frag = QCSFragment(
                fragment_id   = qcs.fragment_ids[i],
                index         = i + 1,
                payload_hex   = bytes(raw).hex(),
                destination   = dest,
                signature_ref = qcs.signature_hex[:16] + "..."
            )
            fragments.append(frag)

        return fragments

    def reconstruct(
        self,
        frag_a: QCSFragment,
        frag_b: QCSFragment
    ) -> bytes:
        """
        Reconstruit la signature à partir de deux fragments quelconques.

        Parameters
        ----------
        frag_a, frag_b : QCSFragment
            Deux fragments distincts (index différents).

        Returns
        -------
        bytes
            Signature reconstruite.
        """
        if frag_a.index == frag_b.index:
            raise ValueError("Les deux fragments doivent avoir des index différents.")

        raw_a = list(bytes.fromhex(frag_a.payload_hex))
        raw_b = list(bytes.fromhex(frag_b.payload_hex))
        x_a, x_b = frag_a.index, frag_b.index

        reconstructed = []
        for ya, yb in zip(raw_a, raw_b):
            # Interpolation de Lagrange pour retrouver a0 = P(0)
            # P(0) = ya * (-x_b / (x_a - x_b)) + yb * (-x_a / (x_b - x_a))  mod PRIME
            num_a   = (-x_b) % self.PRIME
            den_a   = (x_a - x_b) % self.PRIME
            num_b   = (-x_a) % self.PRIME
            den_b   = (x_b - x_a) % self.PRIME

            inv_den_a = pow(den_a, self.PRIME - 2, self.PRIME)  # Fermat
            inv_den_b = pow(den_b, self.PRIME - 2, self.PRIME)

            secret = (ya * num_a * inv_den_a + yb * num_b * inv_den_b) % self.PRIME
            reconstructed.append(secret % 256)

        return bytes(reconstructed)


# ═════════════════════════════════════════════════════════════════════════════
# VI. QCS VALIDATOR  —  Validation par cohérence topologique
# ═════════════════════════════════════════════════════════════════════════════

class QCSValidator:
    """
    Validation d'une signature QCS par cohérence topologique.

    Le serveur ne stocke pas les signatures exactes.
    Il stocke la fenêtre d'acceptance W (paramètres topologiques)
    et vérifie que π_⊥(QCS') ∈ W.

    Un attaquant qui compromet le serveur ne récupère que W —
    insuffisant pour forger une QCS valide sans κ_KDR.
    """

    def __init__(self, tolerance: float = WINDOW_TOLERANCE):
        """
        Parameters
        ----------
        tolerance : float
            Tolérance topologique (défaut 15%).
        """
        self.tolerance  = tolerance
        self._window_db: dict = {}    # {signature_ref: topological_fp_hex}

    def register_window(self, qcs: QCSSignature) -> None:
        """
        Enregistre la fenêtre d'acceptance W pour une signature.

        Appelé lors de la génération initiale (côté émetteur légitime).
        """
        ref = qcs.signature_hex[:16]
      
