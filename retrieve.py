def retrieve_chunks(query, index, chunk_records, embed_model, top_k=3):
    query_embedding = embed_model.encode([query], convert_to_numpy=True).astype("float32")
    distances, indices = index.search(query_embedding, top_k)

    results = []
    for idx in indices[0]:
        results.append(chunk_records[idx])

    return results
