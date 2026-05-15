from pathlib import Path
import shlex
import re
import random
import os
import argparse
import json
import traceback
import yaml
import requests
from queue import Queue
from classification import *
from mutate_logic import *
from execute import ExecuteAgent
from zircolite import ZircoliteAgent
from llm import generate_json_with_model, get_potential_bypass_cmd_with_model
import time
import sys

# --- 1. CONFIGURATION & REGEX ---
SEEDS_DIR = "seeds"  
OUT_DIR = "out"      
JSON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context")
ZIRCOLITE_DETECTED_EVENTS = "../detected_events.json"
script_dir = os.path.dirname(os.path.abspath(__file__))

#DATA STRUCTURE
cache = {}
exec_list = list()
seed_queue = Queue()
execute_queue = Queue()
rule_filename_to_title = {}  # Global dictionary to map filenames to rule titles

#LOGIC FUNCTIONS
def get_exec_list():
    global exec_list
    try:
        with open(os.path.join(JSON_DIR, "exec_list.txt"), "r") as f:
            exec_list = f.readlines()
        return exec_list
    except:
        return

def countdown_sleep(seconds, label="Waiting"):
    """
    Sleep for specified seconds with a countdown display.
    
    Args:
        seconds: Number of seconds to wait
        label: Description of what we're waiting for
    """
    print(f"\n[*] {label} for {seconds} seconds...")
    for remaining in range(seconds, 0, -1):
        mins, secs = divmod(remaining, 60)
        time_str = f"{mins:02d}:{secs:02d}"
        sys.stdout.write(f"\r[*] Time remaining: {time_str} ({remaining}s)  ")
        sys.stdout.flush()
        time.sleep(1)
    print("\n[✓] Done waiting!\n")

def load_rule_filename_mapping():
    """
    Load the rule filename to title mapping from JSON file.
    Populates the global rule_filename_to_title dictionary.
    """
    global rule_filename_to_title
    
    mapping_file = os.path.join(script_dir, "rule_filename_to_title.json")
    
    try:
        if os.path.exists(mapping_file):
            with open(mapping_file, 'r', encoding='utf-8') as f:
                rule_filename_to_title = json.load(f)
            print(f"[+] Loaded {len(rule_filename_to_title)} rule mappings from {mapping_file}")
        else:
            print(f"[!] Warning: {mapping_file} not found. Run parse.py to generate it.")
            rule_filename_to_title = {}
    except Exception as e:
        print(f"[!] Error loading rule filename mapping: {e}")
        rule_filename_to_title = {}


def get_dict_by_json(exec_name):
    
    exec_basename = os.path.basename(exec_name)
    exec_name_clean = os.path.splitext(exec_basename)[0]
    norm_exec_name = exec_name_clean.lower()
    
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
            print(f"[*] JSON file not found for {norm_exec_name}, attempting to generate with model...")
            argument_dict, switch_dict, cmd_dict = generate_json_with_model(norm_exec_name, exec_list)
        except Exception as e:
            print(f"[!] Error reading JSON for {norm_exec_name}: {e}")
        
        # Always populate cache, even if file doesn't exist
        cache[norm_exec_name] = [argument_dict, switch_dict, cmd_dict]
           

def fuzzing(seed_obj, target_count=5, max_attempts=10, verbose=False): 
    """
    Mutate a seed command. 
    seed_obj can be either a string (for backwards compatibility) or a dict with 'command' and 'rule_title' keys.
    """
    # Handle both string and dict seed formats
    if isinstance(seed_obj, dict):
        seed = seed_obj.get('command', '')
        rule_title = seed_obj.get('rule_title', 'unknown')
    else:
        seed = seed_obj
        rule_title = 'unknown'
  
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
            exec_list.append(norm_exec_name)
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
            elif norm_tok in argument_dict or norm_tok in switch_dict or norm_tok in cmd_dict:
                tok_type = "flag"
        
        if tok_type: 
            classified_tokens.append((tok, tok_type))
        else:
            classified_tokens.append((tok, 'unknown'))

    # 3. Mutation Loop
    for i in range(max_attempts):

        new_token_list = []
        
        for original_token, token_type in classified_tokens:
            mutated_token = original_token

            if token_type == "flag":
                
                if original_token in argument_dict:
                    mutated_token = argument_dict[original_token]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = randomize_case(original_token, token_type)
                        case 1:
                            mutated_token = obfuscate_flag(original_token)
                        
                elif original_token in switch_dict:
                    mutated_token = switch_dict[original_token]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = randomize_case(original_token, token_type)
                        case 1: 
                            mutated_token = obfuscate_flag(original_token)

                elif original_token in cmd_dict:
                    mutated_token = cmd_dict[original_token]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = obfuscate_subcommand(mutated_token)
                        case 1:
                            mutated_token = randomize_case(mutated_token, token_type)
                else:
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = obfuscate_flag(original_token)
                        case 1:
                            mutated_token = randomize_case(mutated_token, token_type)
            
            elif token_type == "cmd":
                unquoted_token = original_token.strip('"\'')
                mutated_nested_commands = fuzzing(unquoted_token, target_count=1, max_attempts=1)
                if mutated_nested_commands:
                    mutated_token = f'"{mutated_nested_commands[1]}"'
                else:
                    mutated_token = original_token

            else:
                rand = random.randint(0, 2)
                match rand:
                    case 0:
                        mutated_token = randomize_case(original_token, token_type)
                    case 1:
                        mutated_token = obfuscate_subcommand(mutated_token) #borrow a little bit from subcommand, no prob

            new_token_list.append(mutated_token)

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
        command_obj = execute_queue.get()
        # Handle both string and dict formats
        if isinstance(command_obj, dict):
            command = command_obj.get('command', '')
            rule_title = command_obj.get('rule_title', 'unknown')
        else:
            command = command_obj
            rule_title = 'unknown'
        
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
            execute_queue.put({'command': command, 'rule_title': rule_title})
            all_result.append(result)
        else:
            print(f"Removed commands: {command} (Rule: {rule_title})")
    
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
    zircolite_path_abs = os.path.normpath(os.path.join(script_dir, zircolite_path))
    output_dir_path = os.path.normpath(os.path.join(script_dir, output_dir))
    
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
        print(f"[*] Created output directory '{output_dir}'")
    if not os.path.exists(rules_dir_path):
        print(f"[!] Error: Rules directory '{rules_dir}' not found.")
        return None
    if not events_file:
        print(f"[!] No event files found in '{events_file}'.")
        return None
    print(f"[*] Using Sigma rules from: {rules_dir_path}")
    agent = ZircoliteAgent(
        rules_dir=rules_dir_path,
        events_dir=events_file,
        zircolite_path=zircolite_path_abs,
        output_dir=output_dir_path
    )
    summary = agent.check_events(events_file)
    return summary

#fuzzing loop: get seed from queue -> mutate -> execute batch -> zircolite check -> select successful bypass seed
def fuzzing_loop():
    try:
        while True:
            if seed_queue.qsize() == 0:
                raise KeyboardInterrupt
            curr_seed_obj = seed_queue.get()

            if isinstance(curr_seed_obj, dict):
                curr_seed = curr_seed_obj.get('command', '')
                rule_filename = curr_seed_obj.get('rule_filename', 'unknown')
                rule_title = rule_filename_to_title.get(f"{rule_filename}.yml", "unknown")
            else:
                curr_seed = curr_seed_obj
                rule_filename = 'unknown'
            mutated_command = fuzzing(curr_seed_obj)
            for command in mutated_command:
                execute_queue.put({'command': command, 'rule_title': rule_title})  
            execute()
            #Waiting for Sysmon to logs all events....
            countdown_sleep(100, "Waiting for Sysmon to log all events")

            zircolite_check()

            # Build a mapping of commands to the rules that detected them
            command_rule_map = {}  # {command: [rule_title, ...]}

            with open(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS), "r", encoding='utf-8', errors='replace') as f:
                rules_triggered = json.load(f)

            for rule in rules_triggered:
                rule_title = rule.get("title", "unknown")
                matches = rule.get("matches", [])
                for match in matches:
                    command_line = match.get("CommandLine")
                    if command_line:
                        if command_line not in command_rule_map:
                            command_rule_map[command_line] = []
                        if rule_title not in command_rule_map[command_line]:
                            command_rule_map[command_line].append(rule_title)
                    parent_cmdline = match.get("ParentCommandLine")
                    if parent_cmdline:
                        if parent_cmdline not in command_rule_map:
                            command_rule_map[parent_cmdline] = []
                        if rule_title not in command_rule_map[parent_cmdline]:
                            command_rule_map[parent_cmdline].append(rule_title)
            
            with open('captured.txt', 'a', encoding="utf-8")  as f:
                for cmd, rules in command_rule_map.items():
                    f.write(f"{cmd}\t# Rules: {','.join(rules)}\n")

            curr_batch_length = execute_queue.qsize()

            bypassed_commands = []
            captured_commands = []    
            
            for i in range(curr_batch_length):
                curr_command_obj = execute_queue.get()
                
                # Handle both string and dict formats
                if isinstance(curr_command_obj, dict):
                    curr_command = curr_command_obj.get('command', '')
                    rule_title = curr_command_obj.get('rule_title', 'unknown')
                else:
                    curr_command = curr_command_obj
                    rule_title = 'unknown'
                captured = False
                # Check if the command was captured by the exact rule specified in seed_obj
                if curr_command in command_rule_map:
                    if rule_title in command_rule_map[curr_command]:
                        captured = True
                        print(f"[LOG] Captured command {curr_command} by rule '{rule_title}'")
                        continue
                # Also check if command is substring of any captured command by the correct rule
                for captured_command, rules_that_matched in command_rule_map.items():
                    if rule_title in rules_that_matched and curr_command in captured_command:
                        captured = True
                        print(f"[LOG] Captured command {curr_command} in command-line {captured_command} (Rule: {rule_title})")
                        break   
                if captured == False:
                    bypassed_commands.append(curr_command)
                else:
                    captured_commands.append(curr_command)
            
            print("\n[*] Saving seeds for current rule to file...")
            
    
            # Write commands only for current rule to file
            if len(bypassed_commands) > 0:
                out_dir_path = os.path.join(script_dir, OUT_DIR)
                if not os.path.exists(out_dir_path):
                    os.makedirs(out_dir_path)

                safe_rule_name = re.sub(r'[<>:"|?*\\/]', '_', rule_filename)
                output_file = os.path.join(out_dir_path, f"seed_{safe_rule_name}.txt")
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        for cmd in bypassed_commands:
                            f.write(f"{cmd}\n")
                    print(f"[*] Saved {len(bypassed_commands)} commands for rule '{rule_filename}' to {output_file}")
                except Exception as e:
                    print(f"[!] Error saving commands for rule '{rule_title}': {e}")
            else:
                print(f"[*] No commands to save for rule '{rule_title}'.")
                print(f"[*] Chatting with LLM for potential bypass commands...")
                new_command = get_potential_bypass_cmd_with_model(rule_filename, captured_commands)
                seed_queue.push({"command": new_command, "rule_filename":rule_filename})

    
    except KeyboardInterrupt:
        print("\n[*] Fuzzing loop done. Exiting gracefully...")
    except Exception as e:
        print(f"[!] Error in fuzzing loop: {e}")
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Fuzz command seeds using token-based mutations.")
    parser.add_argument('--seeds-dir', default=SEEDS_DIR, help=f"Directory containing seed files (default: {SEEDS_DIR})")
    parser.add_argument('--out-dir', default=OUT_DIR, help=f"Directory for output files (default: {OUT_DIR})")
    parser.add_argument('--target-count', type=int, default=5, help="Number of mutations per seed (default: 5)")
    parser.add_argument('--max-attempts', type=int, default=50, help="Max attempts to generate unique mutations (default: 50)")
    parser.add_argument('--print', action='store_true', help="Print mutations to console instead of writing to files")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    
    args = parser.parse_args()

    #INITIALIZATION

    script_dir = os.path.dirname(os.path.abspath(__file__))
    seeds_dir_path = os.path.join(script_dir, args.seeds_dir)
    out_dir_path = os.path.join(script_dir, args.out_dir)

    load_rule_filename_mapping()

    if not os.path.exists(seeds_dir_path):
        print(f"[!] Error: Seeds directory '{args.seeds_dir}' not found.")
        return
    
    if not args.print and not os.path.exists(out_dir_path):
        os.makedirs(out_dir_path)
        print(f"[*] Created output directory '{args.out_dir}'")

    # Look for both .json and .txt seed files
    seed_files_json = [f for f in os.listdir(seeds_dir_path) if f.endswith(".json")]
    seed_files_txt = [f for f in os.listdir(seeds_dir_path) if f.endswith(".txt")]
    
    if not seed_files_json and not seed_files_txt:
        print(f"[!] No .json or .txt files found in '{SEEDS_DIR}'.")
        return
    
    print(f"[*] Found {len(seed_files_json)} JSON seed files and {len(seed_files_txt)} TXT seed files. Starting batch processing...")
    
    # Process JSON files
    for filename in seed_files_json:
        input_path = os.path.join(seeds_dir_path, filename)
        print(f"\n---> Processing JSON: {filename}")
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                seed_data = json.load(f)
            
            # seed_data should be a list of dicts with 'title' and 'commands' keys
            if isinstance(seed_data, list):
                for item in seed_data:
                    if isinstance(item, dict):
                        rule_filename = item.get('filename', 'unknown')
                        commands = item.get('commands', [])
                        
                        if isinstance(commands, list):
                            for command in commands:
                                if command and isinstance(command, str) and not command.strip().startswith('#'):
                                    seed_obj = {
                                        'command': command.strip(),
                                        'rule_filename': rule_filename
                                    }
                                    seed_queue.put(seed_obj)
                                    print(f"  Added seed: {command.strip()} (Rule: {rule_filename})")
        except Exception as e:
            print(f"[!] Error reading JSON file {filename}: {e}")
            continue
    
    # Process TXT files (backwards compatibility)
    for filename in seed_files_txt:
        input_path = os.path.join(seeds_dir_path, filename)
        match = re.search(r'(\d+)', filename)
        if match:
            out_filename = f"result_{match.group(1)}.txt"
        else:
            out_filename = f"result_{filename}"
            
        output_path = os.path.join(out_dir_path, out_filename)
        print(f"\n---> Processing TXT: {filename} -> {out_filename}")
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                seeds = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                for seed in seeds:
                    seed_obj = {
                        'command': seed,
                        'rule_filename': filename  # Use filename as rule title for txt files
                    }
                    seed_queue.put(seed_obj)
        except Exception as e:
            print(f"[!] Error reading TXT file {filename}: {e}")
            continue

    #FUZZING LOOP
    fuzzing_loop()

    print(f"\n[*] All done! Check the '{OUT_DIR}' folder.")


if __name__ == "__main__":
    main()


