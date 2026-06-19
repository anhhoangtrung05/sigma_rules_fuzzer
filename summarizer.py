import yaml
import os
import json

base_dir = r"c:\BKCS\purplefuzz_mutator_dev"
list_file = os.path.join(base_dir, "process_creation_rule_names.txt")
rules_dir = os.path.join(base_dir, "windows_process_creation")
out_file = os.path.join(base_dir, "summary_857.txt")

with open(list_file, "r") as f:
    rule_names = [line.strip() for line in f.readlines() if line.strip()][800:857]

summary = []
for r in rule_names:
    yml_path = os.path.join(rules_dir, r + ".yml")
    if os.path.exists(yml_path):
        with open(yml_path, "r", encoding="utf-8") as yf:
            try:
                data = yaml.safe_load(yf)
                detection = data.get("detection", {})
                summary.append(f"RULE: {r}\nDETECTION: {json.dumps(detection)}\n")
            except Exception as e:
                summary.append(f"RULE: {r}\nDETECTION: ERROR {e}\n")

with open(out_file, "w", encoding="utf-8") as outf:
    outf.write("\n".join(summary))
print("Summary of 100 rules written to summary_100.txt")
