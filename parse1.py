import os
import re
import yaml
import json
from pathlib import Path
from typing import Set, Dict


def map_filenames_to_titles(folder_path: str) -> Dict[str, str]:

    filename_to_title = {}
    folder = Path(folder_path)
    
    if not folder.exists():
        print(f"Error: Folder {folder_path} does not exist")
        return filename_to_title
    
    yml_files = list(folder.glob('*.yml')) + list(folder.glob('*.yaml'))
    print(f"Found {len(yml_files)} YAML files in {folder_path}")
    
    for yml_file in sorted(yml_files):
        try:
            with open(yml_file, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
                if rule_data and 'title' in rule_data:
                    title = rule_data['title']
                    filename_to_title[yml_file.name] = title
                    print(f"  {yml_file.name} -> {title}")
                else:
                    print(f"  {yml_file.name} -> [NO TITLE FOUND]")
        except Exception as e:
            print(f"Error parsing {yml_file}: {e}")
    
    return filename_to_title


def main():
    script_dir = Path(__file__).parent
    sigma_folder = script_dir / "windows_process_creation"
    print("\n" + "=" * 80)
    print("\n[2] Mapping filenames to rule titles...")
    print("-" * 80)
    filename_to_title = map_filenames_to_titles(str(sigma_folder))
    
    # Save mapping to JSON
    json_output = script_dir / 'rule_filename_to_title.json'
    with open(json_output, 'w', encoding='utf-8') as f:
        json.dump(filename_to_title, f, indent=2, ensure_ascii=False)
    print(f"\nSaved JSON mapping to: {json_output}")

if __name__ == '__main__':
    main()