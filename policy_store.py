"""
policy_store.py — the RAG component of ConfigGuard.

In a real deployment, POLICY_DOCS would be chunks pulled from your company's
actual network security policy documents (ingested + chunked as in Part B of
the prep guide). For a fast build, they're hardcoded here as short policy
"chunks" — the retrieval mechanism itself is identical either way.

Production embedding: sentence-transformers (all-MiniLM-L6-v2) or an
Anthropic/OpenAI embedding endpoint. For offline testing without downloading
a model, this file also supports a lightweight TF-IDF fallback embedder —
swap `USE_TFIDF_FALLBACK = False` once you have real embeddings running.
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

USE_TFIDF_FALLBACK = True  # flip to False once sentence-transformers is wired in

POLICY_DOCS = [
    "All unused physical interfaces must be administratively shut down to reduce attack surface.",
    "SSH access to network devices must be restricted using an access-control list (ACL) limiting source IPs to the management subnet.",
    "SNMP must never use default community strings such as 'public' or 'private'; use SNMPv3 with authentication where possible.",
    "Telnet is prohibited on all devices; only SSH may be used for remote CLI access.",
    "Every interface facing an untrusted network must have an inbound ACL applied denying traffic not explicitly permitted.",
    "Password/enable secrets must be stored using a hashed format (e.g., 'enable secret', not 'enable password').",
    "NTP must be configured on all devices pointing to an approved internal time source, to ensure accurate log timestamps.",
    "Logging must be configured to send events to a centralized syslog server, not just kept in local device memory.",
]


def _tfidf_embed_all(texts):
    vectorizer = TfidfVectorizer()
    matrix = vectorizer.fit_transform(texts)
    return vectorizer, matrix


def build_index():
    """Returns whatever context the retriever needs to answer queries later."""
    if USE_TFIDF_FALLBACK:
        vectorizer, matrix = _tfidf_embed_all(POLICY_DOCS)
        return {"vectorizer": vectorizer, "matrix": matrix, "docs": POLICY_DOCS}
    else:
        # Production path: from sentence_transformers import SentenceTransformer
        # model = SentenceTransformer("all-MiniLM-L6-v2")
        # vectors = model.encode(POLICY_DOCS)
        raise NotImplementedError("Wire in a real embedding model here for production use.")


def retrieve_policy(query: str, index: dict, k: int = 3):
    """Returns the top-k most relevant policy chunks for a given query/config snippet."""
    if USE_TFIDF_FALLBACK:
        query_vec = index["vectorizer"].transform([query])
        scores = (index["matrix"] @ query_vec.T).toarray().flatten()
        top_idx = np.argsort(scores)[::-1][:k]
        return [index["docs"][i] for i in top_idx if scores[i] > 0]
    else:
        raise NotImplementedError
