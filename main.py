from datetime import datetime

from config import DATA_FILES, CVE_REFERENCE_FILE, RISK_TAX_FILE, OLLAMA_URL, OLLAMA_MODEL, EMBED_MODEL_NAME, TOP_K
from ingest import load_multiple_files, load_prechunked_json, load_risk_taxonomy, risk_taxonomy_to_text, prepare_chunks
from embed_store import build_vector_store
from retrieve import retrieve_chunks
from generate import ask_ollama
from storage import save_run_file


def main():
    run_payload = {
        "run_type": "main",
        "timestamp": datetime.now().isoformat(),
        "model": OLLAMA_MODEL,
        "data_files": [str(p) for p in DATA_FILES],
        "queries": []
    }

    print("Loading risk taxonomy...")
    risk_tax = load_risk_taxonomy(RISK_TAX_FILE)
    taxonomy_text = risk_taxonomy_to_text(risk_tax)
    print("Risk taxonomy loaded")

    print("Loading records...")
    records = load_multiple_files(DATA_FILES)
    print(f"Loaded {len(records)} records")

    print("Preparing chunks...")
    chunk_records = prepare_chunks(records)
    print(f"Prepared {len(chunk_records)} chunks")

    print("Loading CVE reference chunks...")
    cve_chunks = load_prechunked_json(CVE_REFERENCE_FILE)
    print(f"Loaded {len(cve_chunks)} CVE reference chunks")

    chunk_records.extend(cve_chunks)
    print(f"Total chunks after CVE merge: {len(chunk_records)}")

    print("Building vector store...")
    embed_model, index = build_vector_store(chunk_records, EMBED_MODEL_NAME)
    print("Vector store ready")

    query_counter = 0

    while True:
        query = input("\nEnter a question (or type 'exit'): ").strip()

        if query.lower() == "exit":
            break

        query_counter += 1

        retrieved = retrieve_chunks(
            query=query,
            index=index,
            chunk_records=chunk_records,
            embed_model=embed_model,
            top_k=TOP_K
        )

        print("\nTop retrieved chunks:")
        for i, chunk in enumerate(retrieved, start=1):
            print(f"\n[{i}] {chunk['title']}")
            print(f"Source file: {chunk['source_file']}")
            print(f"Line: {chunk['line_number']}")
            print(f"URL: {chunk['url']}")
            print(chunk["text"][:500])

        print("\nGenerating answer...")
        prompt, answer = ask_ollama(
            query=query,
            retrieved_chunks=retrieved,
            taxonomy_text=taxonomy_text,
            ollama_url=OLLAMA_URL,
            ollama_model=OLLAMA_MODEL
        )

        run_payload["queries"].append({
            "query_id": f"query_{query_counter:03d}",
            "query": query,
            "prompt": prompt,
            "response": answer,
            "retrieved_chunks": [
                {
                    "title": chunk.get("title", ""),
                    "url": chunk.get("url", ""),
                    "source": chunk.get("source", ""),
                    "source_file": chunk.get("source_file", ""),
                    "line_number": chunk.get("line_number"),
                    "published_date": chunk.get("published_date", ""),
                    "risk_hint": chunk.get("risk_hint", ""),
                    "exploit_status": chunk.get("exploit_status", ""),
                    "catalog_state": chunk.get("catalog_state", ""),
                    "text": chunk.get("text", "")
                }
                for chunk in retrieved
            ]
        })

        print("\nAnswer:")
        print(answer)

    run_payload["num_queries"] = len(run_payload["queries"])
    file_path = save_run_file("main_run", run_payload)
    print(f"\nSaved run to: {file_path}")


if __name__ == "__main__":
    main()
