import difflib
import csv
import os

def crystal_bleu_score(reference_code: str, generated_code: str) -> float:
    ref_tokens = reference_code.split()
    gen_tokens = generated_code.split()
    matcher = difflib.SequenceMatcher(None, ref_tokens, gen_tokens)
    return matcher.ratio() * 100

with open("report/compilation_results_seal.csv", "r") as infile, \
     open("report/compilation_results_seal_with_bleu.csv", "w", newline='') as outfile:

    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames + ["CrystalBLEU"]
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        llm = row["LLM"]
        task = row["Task"]
        filename = row["Filename"]
        technique = row["Technique"]

        ref_path = f"reference/{task}/{task}_reference.cpp"
        gen_path = f"codes/{llm}/{task}/{technique}/{filename}"

        if os.path.exists(ref_path) and os.path.exists(gen_path):
            with open(ref_path) as f1, open(gen_path) as f2:
                ref_code = f1.read()
                gen_code = f2.read()
                bleu = crystal_bleu_score(ref_code, gen_code)
        else:
            bleu = "NA"

        if bleu != "NA":
            row["CrystalBLEU"] = f"Score: {round(float(bleu), 2)}"
        else:
            row["CrystalBLEU"] = "Score: NA"
        writer.writerow(row)
