"""
RAG system for Healix: per-user vector indexes over profile, medications, prescriptions, and lab reports.

- Embeddings: sentence-transformers all-MiniLM-L6-v2 (384 dims)
- Vector store: FAISS IndexFlatIP with L2-normalized embeddings (cosine via inner product)
- Fallback: pure NumPy cosine similarity when FAISS isn't available
- Retrieval: top-k chunks with metadata
- LLM: Groq chat completion for answer synthesis

This module is framework-agnostic. Flask routes import and use RAGService.
"""
from __future__ import annotations

import os
import math
import json
import threading
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Any

import numpy as np

try:
    import faiss  # type: ignore
    _FAISS_OK = True
except Exception:
    faiss = None  # type: ignore
    _FAISS_OK = False

from sentence_transformers import SentenceTransformer
from groq import Groq


def _l2_normalize(mat: np.ndarray) -> np.ndarray:
    if mat.ndim == 1:
        norm = np.linalg.norm(mat) + 1e-12
        return mat / norm
    norms = np.linalg.norm(mat, axis=1, keepdims=True) + 1e-12
    return mat / norms


def _chunk_text(text: str, target_words: int = 180, overlap_words: int = 40) -> List[str]:
    """Simple word-based chunking with overlap. Approx 100–300 words per chunk.
    Keeps sentence/line breaks when available.
    """
    if not text:
        return []
    words = text.split()
    if not words:
        return []
    chunks = []
    i = 0
    n = len(words)
    size = max(50, target_words)
    overlap = max(0, min(overlap_words, size // 2))
    while i < n:
        j = min(n, i + size)
        chunk = " ".join(words[i:j]).strip()
        if chunk:
            chunks.append(chunk)
        if j >= n:
            break
        i = j - overlap
    return chunks


def _fmt(obj: Any) -> str:
    return str(obj) if obj is not None else ""


def _build_user_corpus(user: Dict[str, Any], meds: List[Dict[str, Any]], prescs: List[Dict[str, Any]], reps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build plain-text documents with metadata for a given user's data."""
    docs: List[Dict[str, Any]] = []

    # Profile
    profile_lines = [
        f"User Profile for {user.get('full_name') or user.get('email')}",
        f"DOB: {_fmt(user.get('dob'))}",
        f"Gender: {_fmt(user.get('gender'))}",
        f"Blood Group: {_fmt(user.get('blood_group'))}",
        f"Height (cm): {_fmt(user.get('height_cm'))}",
        f"Weight (kg): {_fmt(user.get('weight_kg'))}",
        f"Known Conditions: {_fmt(user.get('known_conditions'))}",
        f"Allergies: {_fmt(user.get('allergies'))}",
        f"Food Tolerance: {_fmt(user.get('food_tolerance'))}",
        f"Smoking: {_fmt(user.get('smoking'))}",
        f"Alcohol: {_fmt(user.get('alcohol'))}",
        f"Physical Activity: {_fmt(user.get('physical_activity'))}",
        f"Diet Type: {_fmt(user.get('diet_type'))}",
    ]
    docs.append({
        "type": "profile",
        "text": "\n".join([l for l in profile_lines if l and not l.endswith(": ")]),
        "meta": {"source": "profile"},
    })

    # Medications
    for m in meds:
        tests = m.get("times")
        times = ", ".join(tests) if isinstance(tests, list) else _fmt(tests)
        med_lines = [
            f"Medication: {_fmt(m.get('name'))}",
            f"Brand: {_fmt(m.get('brand_name'))}",
            f"Form: {_fmt(m.get('form'))}",
            f"Strength: {_fmt(m.get('strength'))}",
            f"Dosage: {_fmt(m.get('dosage'))}",
            f"Frequency per day: {_fmt(m.get('frequency_per_day'))}",
            f"Times: {times}",
            f"Duration (days): {_fmt(m.get('duration_days'))}",
            f"Start date: {_fmt(m.get('start_date'))}",
            f"End date: {_fmt(m.get('end_date'))}",
            f"Instructions: {_fmt(m.get('instructions'))}",
            f"Status: {_fmt(m.get('status'))}",
            f"Source: {_fmt(m.get('source'))}",
        ]
        docs.append({
            "type": "medication",
            "text": "\n".join([l for l in med_lines if l and not l.endswith(": ")]),
            "meta": {"source": "medication", "name": m.get("name")},
        })

    # Prescriptions
    for p in prescs:
        lines = [
            f"Prescription by Dr. {_fmt(p.get('doctor'))} on {_fmt(p.get('date'))}",
        ]
        meds_list = p.get("medications") or []
        for med in meds_list:
            lines.append(
                "- {name} | strength: {strength} | dosage: {dosage} | freq/day: {freq} | times: {times} | duration: {dur} days | start: {start} | notes: {notes}".format(
                    name=_fmt(med.get("name")),
                    strength=_fmt(med.get("strength")),
                    dosage=_fmt(med.get("dosage")),
                    freq=_fmt(med.get("frequency_per_day")),
                    times=", ".join(med.get("times", [])) if isinstance(med.get("times"), list) else _fmt(med.get("times")),
                    dur=_fmt(med.get("duration_days")),
                    start=_fmt(med.get("start_date")),
                    notes=_fmt(med.get("instructions")),
                )
            )
        docs.append({
            "type": "prescription",
            "text": "\n".join(lines),
            "meta": {"source": "prescription", "doctor": p.get("doctor"), "date": p.get("date")},
        })

    # Reports
    for r in reps:
        lines = [
            f"Lab Report: {_fmt(r.get('name'))}",
            f"Date: {_fmt(r.get('date'))}",
            f"Summary: {_fmt(r.get('summary'))}",
        ]
        tests = r.get("tests") or []
        for t in tests:
            lines.append(
                "- {name}: {result} {units} (ref: {ref})".format(
                    name=_fmt(t.get("name")),
                    result=_fmt(t.get("result")),
                    units=_fmt(t.get("units")),
                    ref=_fmt(t.get("reference")),
                )
            )
        docs.append({
            "type": "report",
            "text": "\n".join(lines),
            "meta": {"source": "report", "name": r.get("name"), "date": r.get("date")},
        })

    return docs


@dataclass
class _IndexPack:
    index: Any
    ids: List[str]
    texts: Dict[str, str]
    metas: Dict[str, Dict[str, Any]]
    dim: int


class _NumpyIPIndex:
    """Fallback cosine/IP index using NumPy for small datasets."""
    def __init__(self, dim: int):
        self.dim = dim
        self._vecs: np.ndarray = np.zeros((0, dim), dtype=np.float32)
        self._ids: List[int] = []

    def add(self, vecs: np.ndarray):
        if self._vecs.size == 0:
            self._vecs = vecs.astype(np.float32)
        else:
            self._vecs = np.vstack([self._vecs, vecs.astype(np.float32)])

    def search(self, queries: np.ndarray, k: int) -> Tuple[np.ndarray, np.ndarray]:
        # Inner product search; assume queries and vecs normalized
        sims = queries @ self._vecs.T
        idx = np.argsort(-sims, axis=1)[:, :k]
        scores = np.take_along_axis(sims, idx, axis=1)
        return scores, idx


class RAGService:
    def __init__(self, db):
        self.db = db
        self._model_name = os.environ.get("EMBED_MODEL", "all-MiniLM-L6-v2")
        self._model_lock = threading.Lock()
        self._model: Optional[SentenceTransformer] = None
        self._client = Groq(api_key=os.environ.get("GROQ_KEY"))
        self._per_user: Dict[str, _IndexPack] = {}

    # ---------------- Embeddings ----------------
    def _get_model(self) -> SentenceTransformer:
        if self._model is None:
            with self._model_lock:
                if self._model is None:
                    self._model = SentenceTransformer(self._model_name)
        return self._model

    def _embed(self, texts: List[str]) -> np.ndarray:
        model = self._get_model()
        embs = model.encode(texts, show_progress_bar=False, normalize_embeddings=False)
        if not isinstance(embs, np.ndarray):
            embs = np.array(embs)
        embs = embs.astype(np.float32)
        embs = _l2_normalize(embs)
        return embs

    # ---------------- Indexing ----------------
    def _new_index(self, dim: int):
        if _FAISS_OK:
            index = faiss.IndexFlatIP(dim)
        else:
            index = _NumpyIPIndex(dim)
        return index

    def _pack(self, ids: List[str], texts: List[str], metas: List[Dict[str, Any]]) -> _IndexPack:
        if not texts:
            dim = 384  # default for MiniLM
            index = self._new_index(dim)
            return _IndexPack(index=index, ids=[], texts={}, metas={}, dim=dim)

        embs = self._embed(texts)
        dim = embs.shape[1]
        index = self._new_index(dim)
        if _FAISS_OK:
            index.add(embs)
        else:
            index.add(embs)
        return _IndexPack(index=index, ids=ids, texts=dict(zip(ids, texts)), metas=dict(zip(ids, metas)), dim=dim)

    def _search_pack(self, pack: _IndexPack, query: str, k: int = 5) -> List[Tuple[str, float, Dict[str, Any]]]:
        if not pack.ids:
            return []
        q = self._embed([query])  # normalized
        if _FAISS_OK:
            scores, idxs = pack.index.search(q, k)  # type: ignore
        else:
            scores, idxs = pack.index.search(q, k)  # type: ignore
        scores = scores[0]
        idxs = idxs[0]
        out: List[Tuple[str, float, Dict[str, Any]]] = []
        for score, ii in zip(scores.tolist(), idxs.tolist()):
            if ii < 0 or ii >= len(pack.ids):
                continue
            cid = pack.ids[ii]
            out.append((pack.texts[cid], float(score), pack.metas[cid]))
        return out

    # ---------------- Ingestion ----------------
    def ingest_user(self, user_email: str) -> Dict[str, Any]:
        """Build or rebuild the user's index from Mongo collections."""
        user = self.db.users.find_one({"email": user_email})
        if not user:
            raise ValueError("User not found")
        user_id = str(user.get("_id"))

        meds = list(self.db.medications.find({"user_id": user_id}))
        prescs = list(self.db.prescriptions.find({"user_id": user_id}))
        reps = list(self.db.reports.find({"user_id": user_id}))

        docs = _build_user_corpus(user, meds, prescs, reps)
        # Chunk
        chunk_texts: List[str] = []
        chunk_ids: List[str] = []
        chunk_metas: List[Dict[str, Any]] = []
        for di, d in enumerate(docs):
            pieces = _chunk_text(d["text"], target_words=180, overlap_words=40)
            for pi, ch in enumerate(pieces):
                cid = f"{d['type']}:{di}:chunk:{pi}"
                chunk_ids.append(cid)
                chunk_texts.append(ch)
                meta = dict(d.get("meta", {}))
                meta.update({"doc_type": d["type"], "chunk_index": pi})
                chunk_metas.append(meta)

        pack = self._pack(chunk_ids, chunk_texts, chunk_metas)
        self._per_user[user_email] = pack
        return {
            "chunks": len(chunk_ids),
            "docs": len(docs),
            "medications": len(meds),
            "prescriptions": len(prescs),
            "reports": len(reps),
            "faiss": _FAISS_OK,
            "dim": pack.dim,
        }

    # ---------------- Retrieval + LLM ----------------
    def retrieve(self, user_email: str, query: str, k: int = 5) -> List[Dict[str, Any]]:
        pack = self._per_user.get(user_email)
        if not pack:
            # Lazy ingest if not present
            self.ingest_user(user_email)
            pack = self._per_user.get(user_email)
        if not pack or not pack.ids:
            return []
        hits = self._search_pack(pack, query, k=k)
        out = []
        for text, score, meta in hits:
            item = {"text": text, "score": score, "meta": meta}
            out.append(item)
        return out

    def answer(self, user_email: str, query: str, k: int = 5) -> Dict[str, Any]:
        contexts = self.retrieve(user_email, query, k=k)
        context_block = "\n\n".join([f"[Source {i+1} | score={c['score']:.3f}]\n{c['text']}" for i, c in enumerate(contexts)])

        system = (
            "You are Healix AI, a careful medical assistant. "
            "Use only the provided 'Context' from the user's personal health data (profile, prescriptions, medications, reports). "
            "Be concise, safe, and non-diagnostic; recommend consulting a professional when appropriate."
        )

        prompt = (
            "Answer the user's question using ONLY the Context. Cite relevant Source numbers when helpful.\n\n"
            f"Context:\n{context_block or '(no context available)'}\n\n"
            f"Question: {query}\n"
        )

        try:
            chat = self._client.chat.completions.create(
                model=os.environ.get("GROQ_CHAT_MODEL", "llama-3.3-70b-versatile"),
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=600,
            )
            answer = chat.choices[0].message.content
        except Exception as e:
            # Fallback: simple extractive summary of top context
            answer = (
                "I'm unable to reach the AI service right now. Here's the most relevant information I found:\n\n"
                + (contexts[0]["text"] if contexts else "No personal context was available.")
            )

        return {"answer": answer, "sources": contexts}
