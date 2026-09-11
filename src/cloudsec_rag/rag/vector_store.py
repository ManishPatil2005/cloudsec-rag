"""Hybrid Lexical (BM25) & Dense Semantic Vector Store.

Combines Okapi BM25 token scoring with Dense Cosine Similarity and
Reciprocal Rank Fusion (RRF) for high recall across alphanumeric cloud IDs
and natural-language incident concepts. Runs 100% locally with zero external network dependencies.
"""

import math
import re
import zlib
from typing import Dict, List, Optional, Tuple
from ..core.types import BenchmarkReference


class HybridVectorStore:
    """In-memory hybrid retrieval index with BM25 + Dense Semantic Vector support."""

    def __init__(self, vector_dim: int = 128, bm25_k1: float = 1.5, bm25_b: float = 0.75):
        self.vector_dim = vector_dim
        self.k1 = bm25_k1
        self.b = bm25_b

        self.documents: List[BenchmarkReference] = []
        self.doc_texts: List[str] = []
        self.doc_tokens: List[List[str]] = []
        self.doc_vectors: List[List[float]] = []

        # BM25 Statistics
        self.doc_lengths: List[int] = []
        self.avg_doc_length: float = 0.0
        self.idf_cache: Dict[str, float] = {}

    def add_documents(self, documents: List[BenchmarkReference]) -> None:
        """Add benchmark documents to the hybrid index."""
        for doc in documents:
            text = f"{doc.citation_id} {doc.framework} {doc.title} {doc.description} {doc.rationale} {doc.impact} {doc.remediation_command}"
            tokens = self._tokenize(text)
            vector = self._compute_dense_embedding(text)

            self.documents.append(doc)
            self.doc_texts.append(text)
            self.doc_tokens.append(tokens)
            self.doc_lengths.append(len(tokens))
            self.doc_vectors.append(vector)

        # Recalculate BM25 statistics
        num_docs = len(self.documents)
        if num_docs > 0:
            self.avg_doc_length = sum(self.doc_lengths) / num_docs
            self._recalculate_idf()

    def search_hybrid(self, query: str, top_k: int = 3, rrf_k: int = 60) -> List[BenchmarkReference]:
        """Execute hybrid search using Reciprocal Rank Fusion of BM25 and Semantic Cosine Similarity."""
        if not self.documents:
            return []

        # 1. Lexical BM25 Ranking
        bm25_scores = self._score_bm25(query)
        bm25_ranked = sorted(range(len(self.documents)), key=lambda i: bm25_scores[i], reverse=True)

        # 2. Semantic Cosine Ranking
        query_vector = self._compute_dense_embedding(query)
        semantic_scores = [self._cosine_similarity(query_vector, doc_vec) for doc_vec in self.doc_vectors]
        semantic_ranked = sorted(range(len(self.documents)), key=lambda i: semantic_scores[i], reverse=True)

        # 3. Reciprocal Rank Fusion (RRF)
        rrf_scores: Dict[int, float] = {}
        for rank, doc_idx in enumerate(bm25_ranked):
            rrf_scores[doc_idx] = rrf_scores.get(doc_idx, 0.0) + (1.0 / (rrf_k + rank + 1))

        for rank, doc_idx in enumerate(semantic_ranked):
            rrf_scores[doc_idx] = rrf_scores.get(doc_idx, 0.0) + (1.0 / (rrf_k + rank + 1))

        # Sort combined results
        final_ranked = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]

        results = []
        for doc_idx, score in final_ranked:
            ref = self.documents[doc_idx].model_copy()
            cosine_score = semantic_scores[doc_idx]
            bm25_score = bm25_scores[doc_idx]
            normalized_score = min(1.0, max(0.5, (cosine_score * 0.5) + (min(bm25_score, 10.0) / 10.0 * 0.5)))
            ref.similarity_score = round(normalized_score, 4)
            results.append(ref)

        return results

    def _tokenize(self, text: str) -> List[str]:
        """Extract lowercase tokens, splitting words, snake_case, camelCase, and punctuation."""
        # Split camelCase first
        s1 = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', text)
        # Split underscores and hyphens into spaces while preserving raw composite tokens
        tokens = []
        raw_words = re.findall(r"[a-zA-Z0-9_\-\.]+", s1.lower())
        for rw in raw_words:
            tokens.append(rw)
            # Add subwords for snake_case and dashed identifiers
            parts = re.split(r"[_\-\.]+", rw)
            if len(parts) > 1:
                tokens.extend([p for p in parts if len(p) >= 2])
        return tokens

    def _recalculate_idf(self) -> None:
        """Calculate Okapi BM25 Inverse Document Frequency."""
        self.idf_cache.clear()
        total_docs = len(self.documents)
        df: Dict[str, int] = {}

        for tokens in self.doc_tokens:
            unique_terms = set(tokens)
            for term in unique_terms:
                df[term] = df.get(term, 0) + 1

        for term, count in df.items():
            idf = math.log(1.0 + (total_docs - count + 0.5) / (count + 0.5))
            self.idf_cache[term] = max(idf, 0.05)

    def _score_bm25(self, query: str) -> List[float]:
        """Compute BM25 score for query against all documents."""
        q_tokens = self._tokenize(query)
        scores = [0.0] * len(self.documents)

        for i, tokens in enumerate(self.doc_tokens):
            doc_len = self.doc_lengths[i]
            if doc_len == 0 or self.avg_doc_length == 0:
                continue

            tf_dict: Dict[str, int] = {}
            for t in tokens:
                tf_dict[t] = tf_dict.get(t, 0) + 1

            doc_score = 0.0
            for qt in q_tokens:
                if qt in tf_dict:
                    tf = tf_dict[qt]
                    idf = self.idf_cache.get(qt, 0.5)
                    numerator = tf * (self.k1 + 1.0)
                    denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / self.avg_doc_length))
                    doc_score += idf * (numerator / denominator)
            scores[i] = doc_score

        return scores

    def _compute_dense_embedding(self, text: str) -> List[float]:
        """
        Deterministic Subword & Character N-Gram semantic hash embedding using zlib CRC32.
        Produces dense unit-normalized vectors suitable for cosine similarity.
        """
        vector = [0.0] * self.vector_dim
        tokens = self._tokenize(text)

        for token in tokens:
            # Word token contribution
            h_word = zlib.crc32(token.encode("utf-8")) % self.vector_dim
            vector[h_word] += 1.0

            # Subword 3-grams
            if len(token) >= 3:
                for j in range(len(token) - 2):
                    ngram = token[j:j+3]
                    h_gram = zlib.crc32(ngram.encode("utf-8")) % self.vector_dim
                    vector[h_gram] += 0.5

        # L2-normalization
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0.0:
            vector = [v / norm for v in vector]

        return vector

    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Compute cosine similarity between two unit vectors."""
        return sum(a * b for a, b in zip(vec_a, vec_b))
