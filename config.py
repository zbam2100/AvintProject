from pathlib import Path

DATA_FILES = [
    Path("/home/avint/out/poc_20260309/secbert_poc_merged_with_entities.jl"),
    Path("/home/avint/out/poc_20260309/seclists_fd_30d_raw_clean.jl"),
]

RISK_TAX_FILE = Path("/home/avint/risktax.json")

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3"

EMBED_MODEL_NAME = "all-MiniLM-L6-v2"

TOP_K = 5
