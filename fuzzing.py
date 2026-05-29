from pathlib import Path
import shlex
import re
import random
import os
import argparse
import json
import csv
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
ZIRCOLITE_DETECTED_EVENTS = "detected_events.json"
script_dir = os.path.dirname(os.path.abspath(__file__))
LLM_MODE = True

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
           

def fuzzing(seed_obj, target_count=5, max_attempts=30, verbose=False, is_command=True): 
    """
    Mutate a seed command. 
    seed_obj can be either a string (for backwards compatibility) or a dict with 'command' and 'rule_title' keys.
    is_command determines if the seed should be parsed as an executable command or a raw string/sentence.
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
    
    try: 
        original_tokens = shlex.split(seed, posix=False)
    except: 
        return []
    
    # Initialize empty dictionaries to prevent errors if is_command=False
    argument_dict, switch_dict, cmd_dict = {}, {}, {}
    parsed = None

    # --- NEW: Only attempt executable parsing if this is an actual command ---
    if is_command and original_tokens:
        exec_token = original_tokens[0]
        exec_basename = os.path.basename(exec_token)
        exec_name_clean = os.path.splitext(exec_basename)[0]
        norm_exec_name = exec_name_clean.lower()
    
        if norm_exec_name not in cache:
            try:
                get_dict_by_json(norm_exec_name)
                exec_list.append(norm_exec_name)
            except:
                # Fixed to use dict() since argparse try_parse calls .items()
                cache[norm_exec_name] = [dict(), dict(), dict()] 
        
        parsed = try_parse_with_argparse(norm_exec_name, seed, cache[norm_exec_name])
        if verbose and parsed:
            print(f"Parsed command with argparse: {parsed}")

        if norm_exec_name in cache:
            argument_dict, switch_dict, cmd_dict = cache[norm_exec_name]

    # 1. Classify
    classified_tokens = []
    for tok in original_tokens:
        unquoted_token = tok.strip('"\'')
        tok_type = classify_token(unquoted_token)
        if parsed:
            if tok_type == 'literal' and unquoted_token in parsed['parsed_args'].values():
                tok_type = 'argument'

        if tok_type == 'literal':
            # normalize token to see if this might actually be an executable
            tok_basename = os.path.basename(tok)
            tok_name_clean = os.path.splitext(tok_basename)[0]
            norm_tok = tok_name_clean.lower()

            if norm_tok in exec_list:
                tok_type = "executable_name"
            elif norm_tok in argument_dict or norm_tok in switch_dict or norm_tok in cmd_dict:
                tok_type = "flag"
        
        if tok_type: 
            classified_tokens.append((tok, tok_type, unquoted_token))
        else:
            classified_tokens.append((tok, 'unknown', unquoted_token))

    # 3. Mutation Loop
    for i in range(max_attempts):
        new_token_list = []
        
        for original_token, token_type, unquoted_token in classified_tokens:
            mutated_token = original_token

            if token_type == "flag":
                real_flag = unquoted_token.split(':', 1)[0] if ':' in unquoted_token else unquoted_token
                if real_flag in argument_dict:
                    mutated_token = argument_dict[real_flag]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = randomize_case(real_flag, token_type)
                        case 1:
                            mutated_token = obfuscate_flag(real_flag)
                        
                elif real_flag in switch_dict:
                    mutated_token = switch_dict[real_flag]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = randomize_case(real_flag, token_type)
                        case 1: 
                            mutated_token = obfuscate_flag(real_flag)

                elif real_flag in cmd_dict:
                    mutated_token = cmd_dict[real_flag]
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = obfuscate_string(real_flag)
                        case 1:
                            mutated_token = randomize_case(real_flag, token_type)
                else:
                    rand = random.randint(0, 2)
                    match rand:
                        case 0:
                            mutated_token = obfuscate_flag(real_flag)
                        case 1:
                            mutated_token = randomize_case(real_flag, token_type)
                
                if ':' in original_token:
                    mutated_token += ':' + original_token.split(':', 1)[1]
            
            elif token_type == "cmdlet":
                rand = random.randint(0, 2)
                match rand:
                    case 0: 
                        mutated_token = obfuscate_string(original_token)
                    case 1:
                        mutated_token = randomize_case(original_token, token_type)

            elif token_type == "cmd":
                mutated_nested_commands = fuzzing(unquoted_token, target_count=1, max_attempts=1, is_command=True)
                if len(mutated_nested_commands) > 1:
                    mutated_token = f'"{mutated_nested_commands[-1]}"'
                else:
                    mutated_token = original_token

            elif token_type == 'literal' and " " in unquoted_token:
                # Recursive call treating the literal as a raw string, NOT an executable command
                mutated_nested_strings = fuzzing(unquoted_token, target_count=1, max_attempts=1, is_command=False)
                if len(mutated_nested_strings) > 1:
                    mutated_token = f'"{mutated_nested_strings[-1]}"'
                else:
                    mutated_token = original_token

            else:
                mutated_token = original_token
                rand = random.randint(0, 100)
                if rand < 5:
                    mutated_token = randomize_case(original_token, token_type)
                elif rand < 10:
                    mutated_token = obfuscate_string(mutated_token)
                else:
                    mutated_token = original_token

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

#fuzzing loop: get seed from queue -> mutate -> execute batch -> zircolite check (every 20 seeds) -> select successful bypass seed
ZIRCOLITE_CHECK_INTERVAL = 20  # Run Zircolite once every N seeds
def fuzzing_loop():
    seeds_processed = 0 
    pending_commands = []
    llm_call_counts = {} 
    try:
        while True:
            if seed_queue.qsize() == 0:
                raise KeyboardInterrupt
            try:
                curr_seed_obj = seed_queue.get()

                if isinstance(curr_seed_obj, dict):
                    curr_seed = curr_seed_obj.get('command', '')
                    rule_filename = curr_seed_obj.get('rule_filename', 'unknown')
                    rule_title = rule_filename_to_title.get(f"{rule_filename}.yml", "unknown")
                else:
                    curr_seed = curr_seed_obj
                    rule_filename = 'unknown'
                    rule_title = 'unknown'

                mutated_command = fuzzing(curr_seed_obj)
                for command in mutated_command:
                    execute_queue.put({'command': command, 'rule_title': rule_title})
                execute()
                seeds_processed += 1

                # Drain execute_queue into pending_commands
                while not execute_queue.empty():
                    cmd_obj = execute_queue.get()
                    if isinstance(cmd_obj, dict):
                        pending_commands.append({
                            'command':       cmd_obj.get('command', ''),
                            'rule_title':    cmd_obj.get('rule_title', 'unknown'),
                            'rule_filename': rule_filename,
                        })
                    else:
                        pending_commands.append({
                            'command':       cmd_obj,
                            'rule_title':    'unknown',
                            'rule_filename': rule_filename,
                        })

                # Only run Zircolite every ZIRCOLITE_CHECK_INTERVAL seeds
                if seeds_processed % ZIRCOLITE_CHECK_INTERVAL != 0:
                    remaining = ZIRCOLITE_CHECK_INTERVAL - (seeds_processed % ZIRCOLITE_CHECK_INTERVAL)
                    print(f"[*] Seed {seeds_processed}: {len(pending_commands)} commands pending Zircolite check "
                          f"({remaining} seeds until next check).")
                    continue

                print(f"[*] Reached {seeds_processed} seeds — running Zircolite check "
                      f"on {len(pending_commands)} accumulated commands...")
                #Waiting for Sysmon to logs all events....
                countdown_sleep(90, "Waiting for Sysmon to log all events")

                zircolite_check()

                # Build a mapping of commands to the alert rules that detected them.
                command_rule_map = {}  # {command: [{title, id}, ...]}

                with open(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS), "r", encoding='utf-8', errors='replace') as f:
                    rules_triggered = json.load(f)

                for rule in rules_triggered:
                    rule_title_iter = rule.get("title", "unknown")
                    rule_id    = rule.get("id", "unknown")
                    matches    = rule.get("matches", [])
                    for match in matches:
                        for field in ("CommandLine", "ParentCommandLine"):
                            cmdline = match.get(field)
                            if not cmdline:
                                continue
                            entry = command_rule_map.setdefault(cmdline, [])
                            if not any(e['id'] == rule_id for e in entry):
                                entry.append({'title': rule_title_iter, 'id': rule_id})
                
                with open('captured.txt', 'a', encoding="utf-8") as f:
                    for cmd, alert_entries in command_rule_map.items():
                        titles = ','.join(e['title'] for e in alert_entries)
                        f.write(f"{cmd}\t# Rules: {titles}\n")

                # ----------------------------------------------------------------
                # Classify every pending command as bypassed or captured.
                # ----------------------------------------------------------------
                bypassed_by_rule  = {}
                captured_by_rule  = {}
                csv_bypass_rows   = []  
                csv_captured_rows = []  

                for cmd_obj in pending_commands:
                    curr_command  = cmd_obj['command']
                    cmd_rule_title    = cmd_obj['rule_title']
                    cmd_rule_filename = cmd_obj['rule_filename']

                    # Collect all alert entries that matched this command
                    matched_entries = []

                    # Direct match
                    if curr_command in command_rule_map:
                        if cmd_rule_title in [e['title'] for e in command_rule_map[curr_command]]:
                            matched_entries = command_rule_map[curr_command]
                            print(f"[LOG] Captured command {curr_command} by rule '{cmd_rule_title}'")

                    # Substring match (command is contained within a longer logged commandline)
                    if not matched_entries:
                        for logged_cmd, alert_entries in command_rule_map.items():
                            titles = [e['title'] for e in alert_entries]
                            if cmd_rule_title in titles and curr_command in logged_cmd:
                                matched_entries = alert_entries
                                print(f"[LOG] Captured command {curr_command} in command-line {logged_cmd} (Rule: {cmd_rule_title})")
                                break

                    captured = bool(matched_entries)

                    if captured:
                        captured_by_rule.setdefault(cmd_rule_filename, []).append(curr_command)
                        alert_titles = ';'.join(e['title'] for e in matched_entries)
                        alert_ids    = ';'.join(e['id']    for e in matched_entries)
                        csv_captured_rows.append({
                            'rule_filename':  cmd_rule_filename,
                            'rule_name':      cmd_rule_title,
                            'commandline':    curr_command,
                            'alert_rules':    alert_titles,
                            'matched_rule_id': alert_ids,
                        })
                    else:
                        bypassed_by_rule.setdefault(cmd_rule_filename, []).append(curr_command)
                        # Not captured by ANY rule in command_rule_map
                        csv_bypass_rows.append({
                            'rule_filename': cmd_rule_filename,
                            'rule_name':     cmd_rule_title,
                            'commandline':   curr_command,
                        })

                # Clear staging list now that all commands have been classified
                pending_commands.clear()

                # ----------------------------------------------------------------
                # Write .txt seed files (bypassed commands, grouped by rule)
                # ----------------------------------------------------------------
                print("\n[*] Saving seeds for each rule to file...")

                out_dir_path = os.path.join(script_dir, OUT_DIR)
                if not os.path.exists(out_dir_path):
                    os.makedirs(out_dir_path)

                for r_filename, bypassed_commands in bypassed_by_rule.items():
                    safe_rule_name = re.sub(r'[<>:"|?*\\/]', '_', r_filename)
                    output_file = os.path.join(out_dir_path, f"seed_{safe_rule_name}.txt")
                    try:
                        with open(output_file, 'a', encoding='utf-8') as f:
                            for cmd in bypassed_commands:
                                f.write(f"{cmd}\n")
                        print(f"[*] Saved {len(bypassed_commands)} bypassed commands for rule '{r_filename}' to {output_file}")
                    except Exception as e:
                        print(f"[!] Error saving commands for rule '{r_filename}': {e}")

                if not bypassed_by_rule:
                    print("[*] No bypassed commands to save across all rules.")

                # ----------------------------------------------------------------
                # Write CSV logs
                # ----------------------------------------------------------------
                bypass_csv_path   = os.path.join(script_dir, 'commandlines_pass_bypass.csv')
                captured_csv_path = os.path.join(script_dir, 'commandlines_captured.csv')

                bypass_fields   = ['rule_filename', 'rule_name', 'commandline']
                captured_fields = ['rule_filename', 'rule_name', 'commandline', 'alert_rules', 'matched_rule_id']

                for csv_path, fields, rows, label in [
                    (bypass_csv_path,   bypass_fields,   csv_bypass_rows,   'bypass'),
                    (captured_csv_path, captured_fields, csv_captured_rows, 'captured'),
                ]:
                    if not rows:
                        continue
                    write_header = not os.path.exists(csv_path)
                    try:
                        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
                            writer = csv.DictWriter(f, fieldnames=fields)
                            if write_header:
                                writer.writeheader()
                            writer.writerows(rows)
                        print(f"[*] Appended {len(rows)} {label} rows to {csv_path}")
                    except Exception as e:
                        print(f"[!] Error writing {label} CSV: {e}")

                # ----------------------------------------------------------------
                # Ask LLM only for rules where NO bypass was found (all captured)
                # ----------------------------------------------------------------
                all_seen_rules = set(bypassed_by_rule) | set(captured_by_rule)
                for r_filename in all_seen_rules:
                    if r_filename not in bypassed_by_rule:
                        # Fetch the current call count for this specific rule
                        current_llm_count = llm_call_counts.get(r_filename, 0)
                        
                        if current_llm_count < 5:
                            captured_cmds = captured_by_rule.get(r_filename, [])
                            print(f"[*] No bypass found for '{r_filename}' — asking LLM for new candidates... (Attempt {current_llm_count + 1}/5)")
                            new_command = get_potential_bypass_cmd_with_model(r_filename, captured_cmds)
                            seed_queue.put({"command": new_command, "rule_filename": r_filename})
                            
                            # Increment the counter
                            llm_call_counts[r_filename] = current_llm_count + 1
                        else:
                            print(f"[*] Max LLM attempts (5) reached for '{r_filename}'. Skipping LLM call.")
                    else:
                        print(f"[*] Bypass found for '{r_filename}' — skipping LLM call.")
            except Exception as inner_e:
                print(f"[!] Exception during fuzzing iteration. Logging to exception.log and continuing...")
                try:
                    with open("exception.log", "a", encoding="utf-8") as err_log:
                        err_log.write(f"--- Exception at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                        err_log.write(f"Error: {inner_e}\n")
                        traceback.print_exc(file=err_log)
                        err_log.write("-" * 50 + "\n")
                except Exception as log_err:
                    print(f"[!] Failed to write to exception.log: {log_err}")
                
                continue

    except KeyboardInterrupt:
        print("\n[*] Fuzzing loop done. Exiting gracefully...")
    except Exception as e:
        print(f"[!] Critical Error escaping inner fuzzing loop: {e}")
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

    # Look for .json, .txt, and .csv seed files
    seed_files_json = [f for f in os.listdir(seeds_dir_path) if f.endswith(".json")]
    seed_files_txt  = [f for f in os.listdir(seeds_dir_path) if f.endswith(".txt")]
    seed_files_csv  = [f for f in os.listdir(seeds_dir_path) if f.endswith(".csv")]

    if not seed_files_json and not seed_files_txt and not seed_files_csv:
        print(f"[!] No .json, .txt, or .csv files found in '{SEEDS_DIR}'.")
        return

    print(f"[*] Found {len(seed_files_json)} JSON, {len(seed_files_txt)} TXT, "
          f"and {len(seed_files_csv)} CSV seed files. Starting batch processing...")
    
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
                        'rule_filename': filename 
                    }
                    seed_queue.put(seed_obj)
        except Exception as e:
            print(f"[!] Error reading TXT file {filename}: {e}")
            continue

    # Process CSV files — expected columns: target_rule, commandline
    CSV_RULE_COL    = "target_rule"
    CSV_CMD_COL     = "commandline"

    for filename in seed_files_csv:
        input_path = os.path.join(seeds_dir_path, filename)
        print(f"\n---> Processing CSV: {filename}")
        added = 0
        try:
            with open(input_path, 'r', encoding='utf-8-sig') as f: 
                reader = csv.DictReader(f)

                # Validate that the required columns are present
                if reader.fieldnames is None:
                    print(f"[!] CSV file '{filename}' appears to be empty — skipping.")
                    continue

                missing = {CSV_RULE_COL, CSV_CMD_COL} - {c.strip() for c in reader.fieldnames}
                if missing:
                    print(f"[!] CSV file '{filename}' is missing required column(s): "
                          f"{missing}. Found: {reader.fieldnames} — skipping.")
                    continue

                for row_num, row in enumerate(reader, start=2):
                    rule_filename = (row.get(CSV_RULE_COL) or "").strip()
                    command      = (row.get(CSV_CMD_COL)   or "").strip()
                    if not command:
                        print(f"  [!] Row {row_num}: empty '{CSV_CMD_COL}' — skipping.")
                        continue
                    if not rule_filename:
                        print(f"  [!] Row {row_num}: empty '{CSV_RULE_COL}' — skipping.")
                        continue
                    if command.startswith('#'):
                        continue 
                    seed_obj = {
                        'command':       command,
                        'rule_filename': rule_filename,
                    }
                    seed_queue.put(seed_obj)
                    print(f"  Added seed: {command} (Rule: {rule_filename})")
                    added += 1

            print(f"[+] {added} seed(s) loaded from '{filename}'.")

        except Exception as e:
            print(f"[!] Error reading CSV file {filename}: {e}")
            continue

    #FUZZING LOOP
    fuzzing_loop()

    print(f"\n[*] All done! Check the '{OUT_DIR}' folder.")


if __name__ == "__main__":
    main()