import os
import json
import requests
import yaml
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[!] python-dotenv not installed. Install with: pip install python-dotenv")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
    genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
except ImportError:
    GEMINI_AVAILABLE = False

script_dir = os.path.dirname(os.path.abspath(__file__))
JSON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context")
LLM_API_ENDPOINT = "http://100.105.150.19:5002/generate"

def generate_json_with_gemini(exec_name, exec_list):
    """
    Use Gemini AI to generate JSON file with executable flags/arguments.
    Returns dict with argument_dict, switch_dict, cmd_dict structure.
    """
    if not GEMINI_AVAILABLE:
        print(f"[!] Gemini API not available for {exec_name}")
        return [dict(), dict(), dict()]
    
    try:
        prompt = f"""
        Generate a JSON file for the Windows/Linux command '{exec_name}' with the following structure:
        {{
            "-flag1": ["alias_for_flag1", "Argument"],
            "-flag2": ["alias_for_flag2", "Switch"],
            "subcommand": ["alias", "Subcommand"],
            "_meta": {{
                "name": "{exec_name}",
                "type": "executable"
            }}
        }}
        
        Where:
        - "Argument" means the flag takes a value
        - "Switch" means the flag is a boolean toggle
        - "Subcommand" means it's a subcommand
        
        Return ONLY the JSON object, no additional text.

        Example output:
        {{
    "_meta": {{
        "executable": "esentutl.exe",
        "category": "Credential_Access_and_LOLBAS",
        "description": "Extensible Storage Engine Utilities. Frequently abused by threat actors to copy locked system files (like ntds.dit or SAM hives) using Volume Shadow Copies."
    }},
    "/y": ["-y", "Argument"],
    "-y": ["/y", "Argument"],
    "/d": ["-d", "Argument"],
    "-d": ["/d", "Argument"],
    "/vss": ["-vss", "Switch"],
    "-vss": ["/vss", "Switch"],
    "/vssrec": ["-vssrec", "Switch"],
    "-vssrec": ["/vssrec", "Switch"],
    "/r": ["-r", "Argument"],
    "-r": ["/r", "Argument"],
    "/p": ["-p", "Argument"],
    "-p": ["/p", "Argument"],
    "/m": ["-m", "Argument"],
    "-m": ["/m", "Argument"],
    "/g": ["-g", "Argument"],
    "-g": ["/g", "Argument"],
    "/c": ["-c", "Argument"],
    "-c": ["/c", "Argument"],
    "/o": ["-o", "Switch"],
    "-o": ["/o", "Switch"],
    "/8": ["-8", "Argument"],
    "-8": ["/8", "Argument"]
}}
        """
        
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        response = model.generate_content(prompt)
        
        # Parse the response
        response_text = response.text.strip()
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        data = json.loads(response_text)
        argument_dict = dict()
        switch_dict = dict()
        cmd_dict = dict()

        for flag in data:
            if flag == "_meta":
                continue
            info = data[flag]
            if info[1] == "Argument":
                argument_dict[flag] = info[0]
            elif info[1] == "Switch":
                switch_dict[flag] = info[0]
            elif info[1] == "Subcommand":
                cmd_dict[flag] = info[0]

        
        # Save to file
        output_path = os.path.join(JSON_DIR, f"{os.path.basename(exec_name).split('.')[0].lower()}.json")
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Generated and saved JSON for {exec_name}")

        cleaned_exec_name = os.path.basename(exec_name).split('.')[0].lower()
        exec_list_path = os.path.join(JSON_DIR, "exec_list.txt")
        with open(exec_list_path, 'a') as f:
            f.write(f"{cleaned_exec_name}\n")
        
        exec_list.append(cleaned_exec_name)

        return argument_dict, switch_dict, cmd_dict
    
    except Exception as e:
        print(f"[!] Error generating JSON with Gemini for {exec_name}: {e}")
        return
    

def generate_json_with_model(exec_name, exec_list):
    print("[DEBUG] Generating executable dictionary with model.....")
    try:
        prompt = f"""
        You are an expert Cybersecurity Engineer and Systems Architect specialized in command-line forensics and data modeling. Your task is to analyze Windows/Linux executables, PowerShell cmdlets, or scripts provided by the user, and map their parameters into a strict, standardized JSON format.
        Generate a JSON file for the Windows executable '{exec_name}' to list all available flags or subcommands and their aliases/short forms.
        ### REQUIRED JSON SCHEMA:
1. The root must be a single JSON object.
2. The first key must ALWAYS be `"_meta"` containing a `"name"` (the binary name without .exe) and `"type"` (e.g., "executable", "powershell_cmdlet", "python_function").
3. All subsequent keys represent a valid subcommand, switch, or argument.
4. The value for each key MUST be a two-element array: `["Alias_or_Equivalent", "Type"]`.
5. Valid "Type" values are strictly limited to:
   - "Subcommand": A primary action verb (e.g., "use", "create", "list").
   - "Switch": A boolean flag that takes no value (e.g., "/quiet", "-v").
   - "Argument": A flag that requires a trailing value (e.g., "-p <PID>", "/USER:<name>").
6. BIDIRECTIONAL MAPPING IS MANDATORY: If a short-form alias exists for a long-form flag, you must create a key for BOTH, pointing to each other. (If a flag has no alias, map it to "-" or itself).
        ### FEW-SHOT EXAMPLES: For wevtutil.exe:
        {{
    "_meta": {{
        "name": "wevtutil",
        "type": "executable"
    }},
    "clear-log": ["cl", "Subcommand"],
    "cl": ["clear-log", "Subcommand"],
    "query-events": ["qe", "Subcommand"],
    "qe": ["query-events", "Subcommand"],
    "enum-logs": ["el", "Subcommand"],
    "el": ["enum-logs", "Subcommand"],
    "get-log": ["gl", "Subcommand"],
    "gl": ["get-log", "Subcommand"],
    "get-publisher": ["gp", "Subcommand"],
    "gp": ["get-publisher", "Subcommand"],
    "/backup": ["/bu", "Argument"],
    "/bu": ["/backup", "Argument"],
    "/format": ["/f", "Argument"],
    "/f": ["/format", "Argument"],
    "/remote": ["/r", "Argument"],
    "/r": ["/remote", "Argument"],
    "/overwrite": ["/o", "Argument"],
    "/o": ["/overwrite", "Argument"],
    "/config": ["/c", "Argument"],
    "/c": ["/config", "Argument"],
    "/query": ["/q", "Argument"],
    "/q": ["/query", "Argument"]
}}
        Return ONLY the JSON object, no additional text.
        
        """

        req_body = {
            "prompt": prompt,
            "max_tokens": 5500
        }
        response = requests.post(url=LLM_API_ENDPOINT, json=req_body)
        
        response_text = response.text.strip()
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        original_data = json.loads(response_text)
        data =json.loads( original_data.get("response", {}))
        argument_dict = dict()
        switch_dict = dict()
        cmd_dict = dict()

        for flag in data:
            if flag == "_meta":
                continue
            info = data[flag]
            if info[1] == "Argument":
                argument_dict[flag] = info[0]
            elif info[1] == "Switch":
                switch_dict[flag] = info[0]
            elif info[1] == "Subcommand":
                cmd_dict[flag] = info[0]

        
        # Save to file
        output_path = os.path.join(JSON_DIR, f"{os.path.basename(exec_name).split('.')[0].lower()}.json")
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Generated and saved JSON for {exec_name}")

        cleaned_exec_name = os.path.basename(exec_name).split('.')[0].lower()
        exec_list_path = os.path.join(JSON_DIR, "exec_list.txt")
        with open(exec_list_path, 'a') as f:
            f.write(f"{cleaned_exec_name}\n")
        
        exec_list.append(cleaned_exec_name)

        return argument_dict, switch_dict, cmd_dict

    except Exception as e:
        print("[DEBUG] Error happened while connecting to LLM model: ", e)

def get_potential_bypass_cmd_with_model(rule_filename, captured_commands=None):
    script_dir = Path(__file__).parent
    rule_dir = script_dir / "windows_process_creation/windows_process_creation"
    with open(rule_dir / f"{rule_filename}.yml", "r") as f:
        data = yaml.safe_load(f)
    detection_data = data.get('detection', '')

    prompt = f"""
You are an expert in Windows command evasion and Sigma rule bypasses.

**Sigma Rule Target**: {rule_filename}

**Detection rules**:
{json.dumps(detection_data, indent=2)}

**Commands that WERE DETECTED by this rule**:
{json.dumps(captured_commands, indent=2)}

**Task**: Generate a NEW alternative command that achieves the same functionality but might bypass the '{rule_filename}' detection rule.

**Requirements**:
1. The command must be functionally equivalent to the examples above
2. Use different techniques to avoid detection:
- Alternative command syntax or flags
- Obfuscation techniques (case randomization, escaped characters)
- Indirect execution paths
3. Do NOT simply add comments or quotes
4. Do NOT try to use an alternative executable
5. Return ONLY the command string, no explanation

Return ONLY the command, nothing else.
"""
    
    try:
        request_data = {
            "prompt": prompt,
            "max_tokens": 67000
        }
        raw_response = requests.post(url=LLM_API_ENDPOINT, json=request_data)
        if raw_response:
            json_response = json.loads(raw_response.text)
            bypass_command = json_response.get("response").strip()
            print(f"[+] Generated bypass command: {bypass_command}")
            return bypass_command
        else:
            print("[DEBUG] Bypass command no where to be found ???")
            return None
    
    except Exception as e:
        print(f"[!] Error generating bypass command with model: {e}")
        return None

def get_multiple_bypass_cmds_with_model(rule_filename, seed_command, target_count):
    script_dir = Path(__file__).parent
    rule_dir = script_dir / "windows_process_creation/windows_process_creation"
    
    detection_data = ""
    try:
        with open(rule_dir / f"{rule_filename}.yml", "r") as f:
            data = yaml.safe_load(f)
        detection_data = data.get('detection', '')
    except Exception as e:
        print(f"[!] Warning: Could not load rule {rule_filename}.yml: {e}")

    prompt = f"""
You are an expert in Windows command evasion and Sigma rule bypasses.

**Sigma Rule Target**: {rule_filename}

**Detection rules**:
{json.dumps(detection_data, indent=2)}

**Original Seed Command**:
{seed_command}

**Task**: Generate EXACTLY {target_count} NEW, unique alternative commands that achieve the same functionality as the Original Seed Command but might bypass the '{rule_filename}' detection rule.

**Allowed Mutation Techniques**:
You are freely allowed to experiment with one or more of these techniques for each command:
1. Insertion: insert characters such as quotes, spaces, etc.
2. Substitution: replace a flag with its aliases (like -p and --password), replace literal string with its equivalents (like adduser:yes -> adduser:y), replace a character with its version in another encoding (like 'a' replaced by 'ᵃ', make sure this does not break parsing).
3. Reordering: swap the positions of flags and subcommands (like procdump -ls -ma changed into procdump -ma -ls).
4. Omission: omit some flags, arguments in the command that do not change the core behavior of the command (like removing "-v" to exit verbose mode).
5. Encoding: encode the commands using base64, hex encoding, etc.
6. Recoding: recode IP addresses (example: 127.0.0.1 into 2130706433, 127.0.0.1 to ::ffff:7f00:1).
7. Aliasing: Using the same executable, but run it in a different way to achieve the same outcome.
8. Others: If you use techniques other than the seven listed above, specify them clearly.

**Requirements**:
1. The commands must be functionally equivalent to the original seed command.
2. You MUST return a JSON array of objects. Each object must contain the mutated "command" and a list of "techniques" used.
   Example format:
   [
     {{
       "command": "mutated command 1",
       "techniques": ["Insertion", "Substitution"]
     }},
     {{
       "command": "mutated command 2",
       "techniques": ["Others (Custom Encoding)"]
     }}
   ]

Return ONLY the JSON array, no explanation or formatting text.
"""
    
    try:
        request_data = {
            "prompt": prompt,
            "max_tokens": 67000
        }
        raw_response = requests.post(url=LLM_API_ENDPOINT, json=request_data)
        if raw_response:
            json_response = json.loads(raw_response.text)
            response_text = json_response.get("response", "").strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith('```'):
                response_text = response_text.split('```')[1]
                if response_text.startswith('json'):
                    response_text = response_text[4:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
                
            bypass_commands = json.loads(response_text)
            
            if isinstance(bypass_commands, list):
                print(f"[+] Generated {len(bypass_commands)} bypass commands from LLM")
                
                extracted_commands = []
                for item in bypass_commands:
                    if isinstance(item, dict) and "command" in item:
                        techniques = item.get("techniques", [])
                        print(f"    - Command: {item['command']}")
                        print(f"      Techniques: {', '.join(techniques)}")
                        
                        extracted_commands.append({
                            "command": item["command"],
                            "technique": techniques if techniques else ["Unknown"]
                        })
                    elif isinstance(item, str): # Fallback if model just returns strings
                        extracted_commands.append({
                            "command": item,
                            "technique": ["Unknown"]
                        })
                        
                return extracted_commands
            else:
                print(f"[!] LLM did not return a list. Returned type: {type(bypass_commands)}")
                return []
        else:
            print("[DEBUG] Bypass command no where to be found ???")
            return []
    
    except Exception as e:
        print(f"[!] Error generating bypass commands with model: {e}")
        return []

def get_potential_bypass_cmd_with_gemini(rule_filename, captured_commands=None):
    
    script_dir = Path(__file__).parent
    rule_dir = script_dir / "windows_process_creation"
    with open(rule_dir / f"{rule_filename}.yml", "r") as f:
        data = yaml.safe_load(f)
    detection_data = data.get('detection', '')

    prompt = f"""
You are an expert in Windows command evasion and Sigma rule bypasses.

**Sigma Rule Target**: {rule_filename}

**Detection rules**:
{json.dumps(detection_data, indent=2)}

**Commands that WERE DETECTED by this rule**:
{json.dumps(captured_commands, indent=2)}

**Task**: Generate a NEW alternative command that achieves the same functionality but might bypass the '{rule_filename}' detection rule.

**Requirements**:
1. The command must be functionally equivalent to the examples above
2. Use different techniques to avoid detection:
- Alternative command syntax or flags
- Obfuscation techniques (case randomization, escaped characters)
- Different tool alternatives that perform the same action
- Indirect execution paths
3. Do NOT simply add comments or quotes
4. Return ONLY the command string, no explanation

Return ONLY the command, nothing else.
"""

    if not GEMINI_AVAILABLE:
        print(f"[!] Gemini API not available")
        return None
    
    try:
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        response = model.generate_content(prompt)
        
        bypass_command = response.text.strip()
        print(f"[+] Generated bypass command: {bypass_command}")
        return bypass_command
    
    except Exception as e:
        print(f"[!] Error generating bypass command with Gemini: {e}")
        return None