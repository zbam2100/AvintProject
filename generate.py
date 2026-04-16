import requests


def build_prompt(query, retrieved_chunks, taxonomy_text):
    context = "\n\n".join(chunk["text"] for chunk in retrieved_chunks)

    prompt = f"""You are a cybersecurity risk analyst.

Use the risk taxonomy and guidance below as the framework for your reasoning.
Base your answer only on:
1. the risk taxonomy
2. the retrieved vulnerability context

You must give a numerical risk score based on the taxonomy guidelines.
If the context is insufficient, say so clearly.
All threats and indicators should be clearly justified.

RISK TAXONOMY / GUIDELINES:
{taxonomy_text}

RETRIEVED VULNERABILITY CONTEXT:
{context}

USER QUERY:
{query}

Return your answer in this format:

Risk Assessment:
- Overall risk level: 0-100
- Confidence: 0-100
- Short justification:

Threats: 
- Threat 1:
- Threat 2:
- Threat 3:

Affected Assets / Systems:
- ...

Indicators / Relevant Entities:
- ...

Recommended Next Steps:
- ...

Use concise language and do not invent facts that are not supported by the context or taxonomy.
"""
    return prompt


def ask_ollama(query, retrieved_chunks, taxonomy_text, ollama_url, ollama_model):
    prompt = build_prompt(query, retrieved_chunks, taxonomy_text)

    response = requests.post(
        ollama_url,
        json={
            "model": ollama_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        },
        timeout=120
    )

    response.raise_for_status()
    answer = response.json()["message"]["content"]
    return prompt, answer
