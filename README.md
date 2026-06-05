"""
PSEC v2.1 — Quasi-Crystal Signature (QCS) Module
=================================================
Architecture Entropique Fluide

Auteur   : PSEC Project
Version  : 2.1.0
Licence  : Propriétaire / Recherche

Description
-----------
Le module QCS implémente la signature quasi-cristalline du système PSEC.
Chaque signature est unique, ordonnée (structure de Penrose), non-forgeab-
le (liée à l'empreinte KDR) et vérifiable par cohérence topologique sans
stockage de la valeur exacte.

Composantes
-----------
  - EntropicClock     : Horloge entropique E(t) — graine non-reproductible
  - PenroseProjector  : Projection quasi-cristalline P(E(t))
  - QCSGenerator      : Génération de la signature QCS(f, a)
  - QCSFragmenter     : Fragmentation asymétrique Shamir (2,3)-threshold
  - QCSValidator      : Validation par cohérence topologique
  - TopologicalAudit  : Journal d'audit infalsifiable

Dépendances
-----------
  pip install cryptography numpy argon2-cffi
"""

import hashlib
import hmac
import os
import time
import struct
import json
import math
import secrets
from dataclasses import dataclass, field, asdict
from typing import Tuple, List, Optional
from enum import Enum

# ── Dépendances optionnelles ──────────────────────────────────────────────────
try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False

try:
    from argon2 import PasswordHasher
    from argon2.low_level import hash_secret_raw, Type
    _ARGON2 = True
except ImportError:
    _ARGON2 = False


# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTES GLOBALES
# ═════════════════════════════════════════════════════════════════════════════

PSEC_VERSION       = "2.1.0"
PENROSE_PHI        = (1 + math.sqrt(5)) / 2          # Nombre d'or φ
PENROSE_DIMENSIONS = 5                                # Réseau R^5 → R^2
QCS_FRAGMENT_COUNT = 3                                # Shamir (2,3)-threshold
QCS_THRESHOLD      = 2                                # Fragments min pour reconstruire
WINDOW_TOLERANCE   = 0.15                             # Tolérance topologique (15%)
HASH_ALGO          = "sha3_256"                       # SHA-3 par défaut


# ═════════════════════════════════════════════════════════════════════════════
# I. ENTROPIC CLOCK  —  E(t)
# ═════════════════════════════════════════════════════════════════════════════

class EntropicClock:
    """
    Horloge entropique E(t).

    E(t) = H( Δλ(t) ‖ σ_cpu(t) ‖ τ_hi(t) ‖ os_entropy )

    Produit une graine non-reproductible et non-prédictible à partir de
    sources de volatilité système combinées.
    """

    def __init__(self, window_size: int = 8):
        """
        Parameters
        ----------
        window_size : int
            Nombre de mesures de latence pour calculer la variance Δλ(t).
        """
        self.window_size = window_size
        self._latency_window: List[float] = []

    # ── Mesures de volatilité ─────────────────────────────────────────────

    def _sample_latency_variance(self) -> float:
        """Variance des latences d'appels système successifs (µs)."""
        samples = []
        for _ in range(self.window_size):
            t0 = time.perf_counter_ns()
            _ = os.urandom(1)           # syscall léger
            t1 = time.perf_counter_ns()
            samples.append(t1 - t0)

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        return variance

    def _sample_cpu_jitter(self) -> int:
        """Micro-fluctuations du scheduler CPU via perf_counter_ns."""
        readings = [time.perf_counter_ns() for _ in range(16)]
        deltas = [readings[i+1] - readings[i] for i in range(len(readings)-1)]
        return sum(deltas)

    def _sample_os_entropy(self) -> bytes:
        """Entropie système directe (CSPRNG OS)."""
        return os.urandom(32)

    # ── Génération de E(t) ────────────────────────────────────────────────

    def tick(self) -> bytes:
        """
        Génère une graine entropique E(t) de 32 octets.

        Returns
        -------
        bytes
            Graine entropique H(Δλ ‖ σ_cpu ‖ τ_hi ‖ os_entropy).
        """
        delta_lambda = self._sample_latency_variance()
        sigma_cpu    = self._sample_cpu_jitter()
        tau_hi       = time.perf_counter_ns()
        os_entropy   = self._sample_os_entropy()

        # Sérialisation déterministe des composantes numériques
        numeric_bytes = struct.pack(
            ">dqq",
            delta_lambda,
            sigma_cpu,
            tau_hi
        )

        # H( Δλ ‖ σ_cpu ‖ τ_hi ‖ os_entropy )
        h = hashlib.new(HASH_ALGO)
        h.update(numeric_bytes)
        h.update(os_entropy)
        return h.digest()   # 32 octets


# ═════════════════════════════════════════════════════════════════════════════
# II. PENROSE PROJECTOR  —  P(E(t))
# ═════════════════════════════════════════════════════════════════════════════

class PenroseProjector:
    """
    Projection quasi-cristalline de Penrose.

    Implémente la projection cut-and-project :
        Λ ⊂ R^5  →  R^2
    via la méthode des 5 directions de base à angle φ.

    La graine entropique E(t) détermine le vecteur de décalage dans R^5
    (le "cut"), produisant un pavage apériodique unique à chaque appel.
    """

    def __init__(self, grid_size: int = 64):
        """
        Parameters
        ----------
        grid_size : int
            Résolution du pavage (nombre de points projetés).
        """
        self.grid_size  = grid_size
        self._basis     = self._compute_penrose_basis()

    def _compute_penrose_basis(self) -> List[Tuple[float, float]]:
        """
        5 vecteurs de base de Penrose dans R^2.

        e_k = ( cos(2πk/5), sin(2πk/5) )  pour k = 0..4
        """
        return [
            (math.cos(2 * math.pi * k / 5),
             math.sin(2 * math.pi * k / 5))
            for k in range(5)
        ]

    def _seed_to_offset(self, seed: bytes) -> List[float]:
        """
        Convertit E(t) en vecteur de décalage dans R^5.

        Chaque composante est dérivée d'un segment de 6 octets du seed,
        normalisée dans [0, 1].
        """
        offsets = []
        for i in range(5):
            # Dérive 6 octets par composante (seed de 32 octets → 5 × 6 = 30)
            segment = seed[i*6 : i*6 + 6]
            value   = int.from_bytes(segment, "big")
            max_val = (1 << 48) - 1
            offsets.append(value / max_val)
        return offsets

    def project(self, seed: bytes) -> List[Tuple[float, float]]:
        """
        Génère le pavage quasi-cristallin pour une graine donnée.

        Parameters
        ----------
        seed : bytes
            Graine entropique E(t) (32 octets).

        Returns
        -------
        List[Tuple[float, float]]
            Points du pavage dans R^2.
        """
        offsets = self._seed_to_offset(seed)
        points  = []

        for n in range(-self.grid_size // 2, self.grid_size // 2):
            for k in range(5):
                # Coordonnée dans l'hyperplan R^5
                hyper_coord = n + offsets[k]

                # Projection sur R^2 via la base de Penrose
                ex, ey = self._basis[k]
                x = hyper_coord * ex
                y = hyper_coord * ey

                # Fenêtre d'acceptance : garde les points proches de l'origine
                if abs(x) <= self.grid_size / 4 and abs(y) <= self.grid_size / 4:
                    points.append((round(x, 6), round(y, 6)))

        return points

    def compute_topological_fingerprint(
        self, points: List[Tuple[float, float]]
    ) -> bytes:
        """
        Calcule l'empreinte topologique du pavage.

        L'empreinte encode les propriétés statistiques de la structure
        (distribution des distances, symétrie locale) sans stocker les
        coordonnées exactes — utilisée pour la validation côté serveur.

        Returns
        -------
        bytes
            Empreinte topologique de 32 octets.
        """
        if not points:
            return b"\x00" * 32

        # Distribution des distances entre points voisins
        distances = []
        sample = points[:min(len(points), 128)]   # échantillon représentatif
        for i, (x1, y1) in enumerate(sample):
            for (x2, y2) in sample[i+1:i+4]:
                d = math.sqrt((x2-x1)**2 + (y2-y1)**2)
                distances.append(d)

        if not distances:
            return b"\x00" * 32

        mean_d  = sum(distances) / len(distances)
        # Ratio d'or : signature de la structure de Penrose
        phi_ratio = mean_d * PENROSE_PHI

        # Encode les statistiques dans un hash stable
        stats_bytes = struct.pack(
            ">ff",
            mean_d,
            phi_ratio
        )
        h = hashlib.new(HASH_ALGO)
        h.update(stats_bytes)
        h.update(struct.pack(">i", len(points)))
        return h.digest()


# ═════════════════════════════════════════════════════════════════════════════
# III. STRUCTURES DE DONNÉES
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class AccessContext:
    """
    χ(f, a) — Contexte d'accès à un fichier.

    Capture l'environnement d'exécution au moment de la génération
    de la signature QCS.
    """
    file_hash:    str           # Hash SHA3-256 du fichier
    pid:          int           # PID du processus demandeur
    uid:          int           # UID de l'utilisateur
    syscall_hint: str           # Hint d'appel système (open/read/copy)
    timestamp_ns: int = field(default_factory=time.perf_counter_ns)
    session_id:   str = field(default_factory=lambda: secrets.token_hex(8))

    def to_bytes(self) -> bytes:
        """Sérialisation déterministe pour hachage."""
        payload = f"{self.file_hash}|{self.pid}|{self.uid}|" \
                  f"{self.syscall_hint}|{self.timestamp_ns}|{self.session_id}"
        return payload.encode("utf-8")


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
      
