import unittest
from pathlib import Path

from netsentinel.retriever import BM25Retriever, load_techniques, tokenize

KB_PATH = Path(__file__).resolve().parent.parent / "knowledge_base" / "techniques.json"


class RetrieverTests(unittest.TestCase):
    def setUp(self):
        self.retriever = BM25Retriever(load_techniques(KB_PATH))

    def test_tokenize_drops_numbers_and_short_words(self):
        self.assertEqual(tokenize("Failed 203.0.113.45 ssh on it"), ["failed", "ssh"])

    def test_brute_force_logs_rank_brute_force_first(self):
        logs = "Failed password for invalid user admin from 1.2.3.4\nFailed password for root\nAccepted password for deploy"
        top_technique, _ = self.retriever.search(logs, 1)[0]
        self.assertTrue(top_technique.technique_id.startswith("T1110"))

    def test_unrelated_text_returns_nothing(self):
        self.assertEqual(self.retriever.search("zzz qqq xxx", 3), [])

    def test_top_k_limit(self):
        self.assertLessEqual(len(self.retriever.search("dns query txt subdomain", 2)), 2)


if __name__ == "__main__":
    unittest.main()
