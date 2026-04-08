import faiss
from sentence_transformers import SentenceTransformer


def build_vector_store(chunk_records, embed_model_name):
    embed_model = SentenceTransformer(embed_model_name)

    texts = [record["text"] for record in chunk_records]
    embeddings = embed_model.encode(texts, convert_to_numpy=True).astype("float32")

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)

    return embed_model, index
