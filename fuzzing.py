import shlex
import re
import random
import os
import argparse
import json
import sqlite3
import traceback

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[!] python-dotenv not installed. Install with: pip install python-dotenv")

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from queue import Queue

from classification import *
#from database import *
from mutate_logic import *
from execute import ExecuteAgent
from zircolite import ZircoliteAgent
import time

# --- 1. CONFIGURATION & REGEX ---

#DB_FILE = "../fuzzer_tokens.db"
SEEDS_DIR = "seeds"   # Thư mục chứa các file input
OUT_DIR = "out"       # Thư mục chứa các file output

JSON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context")
ZIRCOLITE_DETECTED_EVENTS = "../detected_events.json"
script_dir = os.path.dirname(os.path.abspath(__file__))

#DATA STRUCTURE
cache = {}
exec_list = list()
seed_queue = Queue()
execute_queue = Queue()

#LOGIC FUNCTIONS
def get_exec_list():
    try:
        with open(os.path.join(JSON_DIR, "exec_list.txt"), "r") as f:
            exec_list = f.readlines()
        return exec_list
    except:
        return

def generate_json_with_gemini(exec_name):
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

def get_dict_by_json(exec_name):
    
    # Get just the filename without path
    exec_basename = os.path.basename(exec_name)
    exec_name_clean = os.path.splitext(exec_basename)[0]
    norm_exec_name = exec_name_clean.lower()
    
    # Clean up invalid characters
    norm_exec_name = re.sub(r'[<>:"|?*\s]', '', norm_exec_name)
    
    if not norm_exec_name:
        return None
    
    argument_dict = dict()
    switch_dict = dict()
    cmd_dict = dict()

    if norm_exec_name not in cache:
        try:
            with open(os.path.join(JSON_DIR, f"{norm_exec_name}.json"), "r") as f:
                data = json.load(f)
                
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

        except FileNotFoundError:
            print(f"[*] JSON file not found for {norm_exec_name}, attempting to generate with Gemini...")
            argument_dict, switch_dict, cmd_dict = generate_json_with_gemini(norm_exec_name)
        except Exception as e:
            print(f"[!] Error reading JSON for {norm_exec_name}: {e}")
        
        # Always populate cache, even if file doesn't exist
        cache[norm_exec_name] = [argument_dict, switch_dict, cmd_dict]
           

def fuzzing(seed, target_count=10, max_attempts=10, verbose=False): 
  
    unique_mutated_commands = set()
    unique_mutated_commands.add(seed) 
    mutated_commands_ordered = []
    mutated_commands_ordered.append(seed)

    """
    Assume that the first token in every seed command is the executable path/name
    Check if the list of argument for that executable has been stored in cache.
    If not, load the json file containing arguments info.
    If any exception happens (like a strange executable), store null argument lists in cache.
    """
    try: 
        original_tokens = shlex.split(seed, posix=False)
    except: 
        return []
   
    if original_tokens:
        exec_token = original_tokens[0]
        exec_basename = os.path.basename(exec_token)
        exec_name_clean = os.path.splitext(exec_basename)[0]
        norm_exec_name = exec_name_clean.lower()
    
    if norm_exec_name not in cache:
        try:
            get_dict_by_json(norm_exec_name)
        except:
            cache[norm_exec_name] = [list(), list(), list()]
    
    parsed = try_parse_with_argparse(norm_exec_name, seed, cache[norm_exec_name])
    if verbose and parsed:
        print(f"Parsed command with argparse: {parsed}")

    # 1. Classify
    argument_dict, switch_dict, cmd_dict = cache[norm_exec_name]  
    classified_tokens = []
    for tok in original_tokens:
        tok_type = classify_token(tok)
        if parsed:
            if tok_type == 'literal' and tok in parsed['parsed_args'].values():
                tok_type = 'argument'

        if tok_type == 'literal':
            #normalize token to see if this might actually be an executable
            tok_basename = os.path.basename(tok)
            tok_name_clean = os.path.splitext(tok_basename)[0]
            norm_tok = tok_name_clean.lower()

            if norm_tok in exec_list:
                tok_type = "executable_name"
        
        if tok_type: 
            classified_tokens.append((tok, tok_type))
        else:
            classified_tokens.append((tok, 'unknown'))

    # 3. Mutation Loop
    for i in range(max_attempts):

        new_token_list = []
        
        for original_token, token_type in classified_tokens:
            mutated_token = original_token
            rand = random.randint(0, 100)

            # --- ALGORITHM: 35/30/35 for Executables ---
            if token_type == "executable_name":
                if rand < 65: 
                    mutated_token = obfuscate_executable(original_token)
            
            # --- ALGORITHM: 5/55/30/20 for Flags ---
            elif token_type == "flag":
                if rand < 20: 
                    mutated_token = randomize_case(original_token, token_type)
                elif rand < 70: 
                    mutated_token = obfuscate_flag(original_token)
                else:
                    if original_token in argument_dict:
                        mutated_token = argument_dict[original_token]
                    elif original_token in switch_dict:
                        mutated_token = switch_dict[original_token]
                    elif original_token in cmd_dict:
                        mutated_token = cmd_dict[original_token]
            
            elif token_type == "cmd":
                unquoted_token = original_token.strip('"\'')
                mutated_nested_commands = fuzzing(unquoted_token, target_count=1, max_attempts=1)
                if mutated_nested_commands:
                    mutated_token = f'"{mutated_nested_commands[1]}"'
                else:
                    mutated_token = original_token

            else:
                if should_randomize_case(token_type, original_token) and rand <= 50:  # 5-30: case mutation for strings
                    mutated_token = randomize_case(original_token, token_type)

            new_token_list.append(mutated_token)
        
        # Apply noise flag (Removed, seem useless)
        #if random.random() < 0.5:
            #new_token_list = add_noise_flags(new_token_list, switch_dict)
         
        final_command = " ".join(
            f'"{tok}"' if " " in str(tok) and not (str(tok).startswith('"') and str(tok).endswith('"')) else str(tok) 
            for tok in new_token_list
        )
        
        if final_command not in unique_mutated_commands:
            unique_mutated_commands.add(final_command)
            mutated_commands_ordered.append(final_command)
    
    return mutated_commands_ordered


def execute(shell='powershell', timeout=10):
    """
    Execute all mutated command files in the output directory.
    Check stderr for syntax errors and skip those commands.
    """
    agent = ExecuteAgent(shell=shell, timeout=timeout)

    all_result = list()

    curr_batch_length = execute_queue.qsize()
    for i in range(curr_batch_length):
        command = execute_queue.get()
        result = agent.execute_command(command)
        
        # Check for syntax errors in stderr
        has_syntax_error = False
        if result:
            stderr_content = None
            stdout_content = None
            if isinstance(result, dict) and 'stderr' in result:
                stderr_content = result.get('stderr')
            elif hasattr(result, 'stderr'):
                stderr_content = result.stderr
            if isinstance(result, dict) and 'stdout' in result:
                stdout_content = result.get('stdout')
            elif hasattr(result, 'stdout'):
                stdout_content = result.get('stdout')
            syntax_error_keywords = [
                    'syntax error',
                    'unexpected token',
                    'is not recognized',
                    'invalid syntax',
                    'parse error',
                    'could not be loaded',
                    'Access is denied',
                ]

            if stderr_content:
                stderr_lower = str(stderr_content).lower()   
                if  any(keyword in stderr_lower for keyword in syntax_error_keywords):
                    has_syntax_error = True
            
            if stdout_content:
                stdout_lower = str(stdout_content).lower()
                if  any(keyword in stdout_lower for keyword in syntax_error_keywords):
                    has_syntax_error = True
        
        # Only push back and collect result if no syntax error
        if not has_syntax_error:
            execute_queue.put(command)
            all_result.append(result)
        else:
            print(f"Removed commands: {command}")
    
    return all_result


def zircolite_check(
    rules_dir='./windows_process_creation',
    events_file='C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx',
    zircolite_path='../Zircolite/zircolite.py',
    output_dir='./zircolite_output'
):
    """
    Run Zircolite detection on event files using Sigma rules.
    """

    rules_dir_path = os.path.normpath(os.path.join(script_dir, rules_dir))
    #events_dir_path = os.path.normpath(os.path.join(script_dir, events_dir))
    zircolite_path_abs = os.path.normpath(os.path.join(script_dir, zircolite_path))
    output_dir_path = os.path.normpath(os.path.join(script_dir, output_dir))
    
    # Create output directory if not exists
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
        print(f"[*] Created output directory '{output_dir}'")
    
    # Check if rules directory exists
    if not os.path.exists(rules_dir_path):
        print(f"[!] Error: Rules directory '{rules_dir}' not found.")
        return None
    
    # Check if events directory exists
    #if not os.path.exists(events_dir_path):
        #print(f"[!] Error: Events directory '{events_dir}' not found.")
        #return None
    
    # Get all event files
    #event_files = [f for f in os.listdir(events_dir_path) if f.endswith(('.json', '.jsonl', '.log'))]
    
    if not events_file:
        print(f"[!] No event files found in '{events_file}'.")
        return None
    
    #print(f"[*] Found {len(event_files)} event file(s). Starting Zircolite detection...")
    print(f"[*] Using Sigma rules from: {rules_dir_path}")
    
    # Initialize ZircoliteAgent
    agent = ZircoliteAgent(
        rules_dir=rules_dir_path,
        events_dir=events_file,
        zircolite_path=zircolite_path_abs,
        output_dir=output_dir_path
    )
    
    # Full paths to event files
    #event_file_paths = [os.path.join(events_dir_path, f) for f in event_files]
    
    # Run batch analysis
    #summary = agent.analyze_batch(event_file_paths)

    summary = agent.check_events(events_file)
    
    return summary

#fuzzing loop: get seed from queue -> mutate -> execute batch -> zircolite check -> select successful bypass seed
def fuzzing_loop():
    try:
        #temporary 5 loops first hehe
        loop = 0
        while True:
            loop = loop + 1
            #Push curr_seed to back of the queue
            if seed_queue.qsize() == 0:
                raise KeyboardInterrupt
            
            if loop > 5:
                raise KeyboardInterrupt

            curr_seed = seed_queue.get()
            seed_queue.put(curr_seed)

            mutated_command = fuzzing(curr_seed)
            
            for command in mutated_command:
                execute_queue.put(command)
            
            all_result = execute()

            #Waiting for Sysmon to logs all events....
            time.sleep(5)

            zircolite_check()

            captured_commands = list()
            with open(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS), "r") as f:
                rules_triggered = json.load(f)

            for rule in rules_triggered:
                matches = rule.get("matches", [])
                for match in matches:
                    command_line = match.get("CommandLine")
                    if command_line:
                        captured_commands.append(command_line)
                    parent_cmdline = match.get("ParentCommandLine")
                    if parent_cmdline:
                        captured_commands.append(parent_cmdline)
            
            with open('captured.txt', 'a')  as f:
                f.write('\n'.join(cmd for cmd in captured_commands))

            curr_batch_length = execute_queue.qsize()

            for i in range(curr_batch_length):
                curr_command = execute_queue.get()
                captured = False

                if curr_command in captured_commands:
                    captured = True
                    print(f"Captured command {curr_command} in command-lines")
                    continue

                for captured_command in captured_commands:
                    if curr_command in captured_command:
                        captured = True
                        print(f"Captured command {curr_command} in command-line {captured_command}")
                        break
                if captured == False:
                    seed_queue.put(curr_command)
            
            print("\n[*] Saving seeds to file...")
            commands_by_exec = {}

            curr_seed_size = seed_queue.qsize()

            for i in range(curr_seed_size):
                command = seed_queue.get()
                seed_queue.put(command) #Pop and push back to queue
                try:
                    tokens = shlex.split(command, posix=False)
                    if tokens:
                        exec_token = tokens[0]
                        exec_basename = os.path.basename(exec_token)
                        exec_name = os.path.splitext(exec_basename)[0].lower()
                        print(f"Found {exec_name} for command {command}")
                    else:
                        exec_name = "unknown"
                except:
                    exec_name = "unknown"

                if exec_name not in commands_by_exec:
                    commands_by_exec[exec_name] = []
                commands_by_exec[exec_name].append(command)
    
            # Write grouped commands to files
            if commands_by_exec:
                out_dir_path = os.path.join(script_dir, OUT_DIR)
                if not os.path.exists(out_dir_path):
                    os.makedirs(out_dir_path)
        
                for exec_name, commands in commands_by_exec.items():
                    output_file = os.path.join(out_dir_path, f"seed_{exec_name}.txt")
                    try:
                        with open(output_file, 'w', encoding='utf-8') as f:
                            for command in commands:
                                f.write(command + '\n')
                        print(f"[*] Saved {len(commands)} commands for '{exec_name}' to {output_file}")
                    except Exception as e:
                        print(f"[!] Error saving commands for '{command}': {e}")
            else:
                print("[*] No commands to save.")
    
    except KeyboardInterrupt:
        print("\n[*] Fuzzing loop interrupted by user (Ctrl+C). Exiting gracefully...")
    except Exception as e:
        print(f"[!] Error in fuzzing loop: {e}")
        traceback.print_exc()
    
    # Save all commands in seed_queue grouped by executable name
    
   
   
def main():
    parser = argparse.ArgumentParser(description="Fuzz command seeds using token-based mutations.")
    parser.add_argument('--seeds-dir', default=SEEDS_DIR, help=f"Directory containing seed files (default: {SEEDS_DIR})")
    parser.add_argument('--out-dir', default=OUT_DIR, help=f"Directory for output files (default: {OUT_DIR})")
    parser.add_argument('--target-count', type=int, default=5, help="Number of mutations per seed (default: 5)")
    parser.add_argument('--max-attempts', type=int, default=50, help="Max attempts to generate unique mutations (default: 50)")
    parser.add_argument('--print', action='store_true', help="Print mutations to console instead of writing to files")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    
    args = parser.parse_args()
    
    #conn, cursor = sqlite_connect()

    #INITIALIZATION

    script_dir = os.path.dirname(os.path.abspath(__file__))
    seeds_dir_path = os.path.join(script_dir, args.seeds_dir)
    out_dir_path = os.path.join(script_dir, args.out_dir)
    # Kiểm tra/Tạo thư mục
    if not os.path.exists(seeds_dir_path):
        print(f"[!] Error: Seeds directory '{args.seeds_dir}' not found.")
        return
    
    if not args.print and not os.path.exists(out_dir_path):
        os.makedirs(out_dir_path)
        print(f"[*] Created output directory '{args.out_dir}'")

    # Lấy danh sách file seeds
    seed_files = [f for f in os.listdir(seeds_dir_path) if f.endswith(".txt")]
    if not seed_files:
        print(f"[!] No .txt files found in '{SEEDS_DIR}'.")
        return
    print(f"[*] Found {len(seed_files)} seed files. Starting batch processing...")

    #Get executable list
    exec_list = get_exec_list()
    
    # Duyệt qua từng file
    for filename in seed_files:
        input_path = os.path.join(seeds_dir_path, filename)
        match = re.search(r'(\d+)', filename)
        if match:
            out_filename = f"result_{match.group(1)}.txt"
        else:
            out_filename = f"result_{filename}"
            
        output_path = os.path.join(out_dir_path, out_filename)
        
        print(f"\n---> Processing: {filename} -> {out_filename}")
        
        with open(input_path, 'r', encoding='utf-8') as f:
            seeds = [line.strip() for line in f if line.strip() and not line.startswith('#')]
 
            for seed in seeds:
                seed_queue.put(seed)

    
    #FUZZING LOOP

    fuzzing_loop()

    print(f"\n[*] All done! Check the '{OUT_DIR}' folder.")



if __name__ == "__main__":
    main()


