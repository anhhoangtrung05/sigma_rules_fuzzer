from pathlib import Path

# The exact path from your error message
target_path = Path(r"C:\Users\bkcs\purple_fuzz_mutator_dev\sigma_rules_fuzzer\windows_process_creation")

print(f"[*] Does the directory exist? {target_path.exists()}")

if target_path.exists():
    print(f"[*] Here is exactly what Python sees inside this directory:")
    for file in target_path.iterdir():
        # Using repr() to expose any hidden spaces or weird characters
        print(f"    {repr(file.name)}")
else:
    print("[!] Python cannot find the folder itself. Check the parent folders for typos.")