#!/usr/bin/env python3
"""
Parse sigma rules from windows_process_creation folder and extract
all executables involved in detection rules.
"""

import os
import re
import yaml
import json
from pathlib import Path
from typing import Set, Dict

def normalize_executable(exe_name: str) -> str:
    """
    Normalize executable name:
    - Remove leading/trailing backslashes and quotes
    - Convert to lowercase
    - Remove .exe, .dll, .sys, .msi extensions
    - Return just the executable name
    
    Examples:
        \7z.exe -> 7z
        certutil.exe -> certutil
        C:\Windows\System32\cmd.exe -> cmd
        %System32%\notepad.exe -> notepad
    """
    # Remove quotes
    exe_name = exe_name.strip('\'"')
    
    # Remove common path prefixes and keep only the filename
    exe_name = os.path.basename(exe_name)
    
    # Remove common extensions
    exe_name = re.sub(r'\.(exe|dll|sys|msi|com|bat|cmd|ps1|vbs|js|jar)$', '', exe_name, flags=re.IGNORECASE)
    
    # Convert to lowercase
    exe_name = exe_name.lower()
    
    return exe_name


def extract_executables_from_rule(rule_data: dict) -> Set[str]:
    """
    Extract executables from a sigma rule.
    Looks for Image, ParentImage, OriginalFileName fields with endswith or other patterns.
    """
    executables = set()
    
    if 'detection' not in rule_data:
        return executables
    
    detection = rule_data['detection']
    
    # Iterate through all selection sections
    for key, value in detection.items():
        if key == 'condition' or not isinstance(value, dict):
            continue
        
        # Check for Image, ParentImage, OriginalFileName fields
        for field_key, field_value in value.items():
            # Handle fields like "Image|endswith", "ParentImage|endswith", "OriginalFileName"
            field_name = field_key.split('|')[0].lower()
            
            if field_name in ['image', 'parentimage', 'originalfilename']:
                # field_value can be a string or a list
                if isinstance(field_value, str):
                    exe = normalize_executable(field_value)
                    if exe:
                        executables.add(exe)
                elif isinstance(field_value, list):
                    for item in field_value:
                        if isinstance(item, str):
                            exe = normalize_executable(item)
                            if exe:
                                executables.add(exe)
    
    return executables


def parse_sigma_rules(folder_path: str) -> Set[str]:
    """
    Parse all YAML sigma rules in a folder and extract unique executables.
    """
    all_executables = set()
    folder = Path(folder_path)
    
    if not folder.exists():
        print(f"Error: Folder {folder_path} does not exist")
        return all_executables
    
    yml_files = list(folder.glob('*.yml')) + list(folder.glob('*.yaml'))
    print(f"Found {len(yml_files)} YAML files in {folder_path}")
    
    for yml_file in sorted(yml_files):
        try:
            with open(yml_file, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
                if rule_data:
                    exes = extract_executables_from_rule(rule_data)
                    all_executables.update(exes)
                    if exes:
                        print(f"  {yml_file.name}: {', '.join(sorted(exes))}")
        except Exception as e:
            print(f"Error parsing {yml_file}: {e}")
    
    return all_executables





def main():
    """Main function."""
    # Get the windows_process_creation folder
    script_dir = Path(__file__).parent
    sigma_folder = script_dir / 'windows_process_creation'
    
    print(f"Parsing sigma rules from: {sigma_folder}")
    print("-" * 80)
    
    # Extract all executables
    print("\n[1] Extracting executables from rules...")
    executables = parse_sigma_rules(str(sigma_folder))
    
    # Sort and save to file
    sorted_executables = sorted(executables)
    
    print("-" * 80)
    print(f"\nFound {len(sorted_executables)} unique executables")
    print("\nExecutables:")
    for exe in sorted_executables:
        print(f"  {exe}")
    
    # Save executables to file
    output_file = script_dir / 'extracted_executables.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_executables))
    
    print(f"\nSaved to: {output_file}")
    
    
    
    # Save mapping to text file
    txt_output = script_dir / 'rule_filename_to_title.txt'
    with open(txt_output, 'w', encoding='utf-8') as f:
        for filename, title in sorted(filename_to_title.items()):
            f.write(f"{filename}\t{title}\n")
    print(f"Saved text mapping to: {txt_output}")
    
    print(f"\nTotal rules mapped: {len(filename_to_title)}")


if __name__ == '__main__':
    main()
