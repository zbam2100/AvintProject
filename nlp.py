from transformers import pipeline
import json
from collections import defaultdict
from tqdm import tqdm

MODEL = "cisco-ai/SecureBERT2.0-NER"
NER = pipeline("token-classification", model=MODEL, aggregation_strategy="simple")

input_file = "out/poc_20260309/secbert_poc_merged.jl"
output_file = "out/poc_20260309/slecbert_poc_merged_with_entities.jl"

with open(input_file, "r") as fin:
    lines = fin.readlines()

with open(output_file, "w") as fout:
    for line in tqdm(lines, desc="Processing", unit="rows", dynamic_ncols=True):
        line = line.strip()
        if not line:
            continue

        entry = json.loads(line)
        grouped_entities = defaultdict(set)

        if "summary" in entry and entry["summary"]:
            entities = NER(entry["summary"])
            for e in entities:
                grouped_entities[e["entity_group"]].add(e["word"])

        for group, words in grouped_entities.items():
            entry[group] = sorted(words)

        fout.write(json.dumps(entry) + "\n")


