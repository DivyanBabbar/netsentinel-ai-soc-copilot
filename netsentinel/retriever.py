"""BM25 retrieval over the technique knowledge base (standard library only)."""
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

WORD_PATTERN = re.compile(r"[a-z]{3,}")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "were",
    "has", "have", "not", "can", "may", "its", "into", "over", "than", "then",
    "also", "such", "when", "which", "any", "all", "but", "out", "use", "used", "using",
}


def tokenize(text):
    """Lowercase, keep words of 3+ letters, drop stopwords. Numbers and IPs are ignored."""
    words = WORD_PATTERN.findall(text.lower())
    return [word for word in words if word not in STOPWORDS]


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    description: str
    detection: str
    response: str

    def as_context(self):
        return (
            f"[{self.technique_id}] {self.name}\n"
            f"What it is: {self.description}\n"
            f"What to look for: {self.detection}\n"
            f"Response: {self.response}"
        )


def load_techniques(path):
    """Read a JSON list of techniques from disk."""
    with open(Path(path), encoding="utf-8") as file:
        rows = json.load(file)
    return [
        Technique(
            technique_id=row["id"],
            name=row["name"],
            description=row["description"],
            detection=row.get("detection", ""),
            response=row.get("response", ""),
        )
        for row in rows
    ]


class BM25Retriever:
    """Ranks techniques against a block of log text using BM25."""

    def __init__(self, techniques, k1=1.5, b=0.75):
        self.techniques = list(techniques)
        self.k1 = k1
        self.b = b
        self.term_counts_per_doc = []
        for technique in self.techniques:
            # The name is repeated so it counts a little more than the body text.
            text = (technique.name + " ") * 2 + technique.description + " " + technique.detection
            self.term_counts_per_doc.append(Counter(tokenize(text)))
        self.doc_lengths = [sum(counts.values()) for counts in self.term_counts_per_doc]
        self.avg_doc_length = sum(self.doc_lengths) / max(1, len(self.doc_lengths))
        self.doc_frequency = Counter()
        for counts in self.term_counts_per_doc:
            for term in counts:
                self.doc_frequency[term] += 1

    def inverse_document_frequency(self, term):
        total_docs = len(self.techniques)
        docs_with_term = self.doc_frequency.get(term, 0)
        return math.log(1 + (total_docs - docs_with_term + 0.5) / (docs_with_term + 0.5))

    def score_document(self, query_terms, doc_index):
        counts = self.term_counts_per_doc[doc_index]
        doc_length = self.doc_lengths[doc_index]
        score = 0.0
        for term in query_terms:
            term_count = counts.get(term, 0)
            if term_count == 0:
                continue
            length_norm = 1 - self.b + self.b * doc_length / self.avg_doc_length
            score += self.inverse_document_frequency(term) * (
                term_count * (self.k1 + 1) / (term_count + self.k1 * length_norm)
            )
        return score

    def search(self, query, top_k=3):
        """Return up to top_k (technique, score) pairs, best first, dropping zero scores."""
        query_terms = set(tokenize(query))
        scored = [
            (technique, self.score_document(query_terms, index))
            for index, technique in enumerate(self.techniques)
        ]
        scored = [pair for pair in scored if pair[1] > 0]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]
