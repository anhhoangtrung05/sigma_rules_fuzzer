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
from llm import generate_json_with_model, get_potential_bypass_cmd_with_model, get_multiple_bypass_cmds_with_model
import time
import sys
import datetime
import subprocess
import xml.etree.ElementTree as ET

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
all_extracted_record_ids = set()
queried_commands = set()
tree_mapping = {}

# Global Stats
stats_total_executed = 0
stats_total_failed = 0
stats_bypass_target_only = 0
stats_bypass_all = 0
stats_captured_by_target = 0
rule_states = {} # rule_title -> state ('CAPTURED', 'BYPASS_ONE', 'BYPASS_ALL')

#LOGIC FUNCTIONS
def get_exec_list():
    global exec_list
    try:
        with open(os.path.join(JSON_DIR, "exec_list.txt"), "r") as f:
            exec_list = f.readlines()
        return exec_list
    except:
        return

def get_latest_sysmon_record_id():
    script = """
    $ErrorActionPreference = 'Stop'
    try {
      $event = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
      if ($null -eq $event) { '0' } else { [string]$event.RecordId }
    } catch {
      Write-Error $_.Exception.Message
      exit 1
    }
    """
    import base64
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
    if proc.returncode == 0:
        text = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        try:
            return int(text)
        except ValueError:
            return 0
    return 0

def find_relevant_logs(pending_commands, start_record_id):
    global all_extracted_record_ids, queried_commands, tree_mapping
    valid_cmds = [c for c in pending_commands if c['command'] not in queried_commands]

    if not valid_cmds:
        return
        
    for c in valid_cmds:
        queried_commands.add(c['command'])

    query = f"*[System[(EventID=1) and (EventRecordID>{start_record_id})]]"
    wevtutil_cmd = ['wevtutil', 'qe', 'Microsoft-Windows-Sysmon/Operational', f'/q:{query}', '/e:Events']

    
    try:
        proc = subprocess.run(wevtutil_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        xml_output = proc.stdout

    except Exception as e:
        print(f"[!] Error running wevtutil qe: {e}")
        return
        
    if not xml_output or not xml_output.strip():
        return

        
    try:
        root = ET.fromstring(xml_output)
    except Exception as e:
        print(f"[!] XML parsing error: {e}")
        return

    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    command_strings = [c['command'] for c in valid_cmds]
    
    # 1. Phase 1: Parse all events into a simpler dictionary list
    parsed_events = []
    for event in root.findall('ns:Event', ns):
        system_node = event.find('ns:System', ns)
        if system_node is None: continue
        
        event_record_id_node = system_node.find('ns:EventRecordID', ns)
        if event_record_id_node is None: continue
        record_id = event_record_id_node.text
        
        event_data_node = event.find('ns:EventData', ns)
        if event_data_node is None: continue
            
        cmdline = ""
        parent_cmdline = ""
        process_guid = ""
        parent_process_guid = ""
        for data in event_data_node.findall('ns:Data', ns):
            name = data.get('Name')
            text = data.text or ""
            if name == 'CommandLine': cmdline = text
            elif name == 'ParentCommandLine': parent_cmdline = text
            elif name == 'ProcessGuid': process_guid = text
            elif name == 'ParentProcessGuid': parent_process_guid = text
            
        parsed_events.append({
            'record_id': record_id,
            'cmdline': cmdline,
            'parent_cmdline': parent_cmdline,
            'process_guid': process_guid,
            'parent_process_guid': parent_process_guid
        })

    # 2. Phase 2: Identify Root Events and populate tree_mapping
    known_guids = {} # maps ProcessGuid -> root_command
    for ev in parsed_events:
        cmdline_norm = " ".join(ev['cmdline'].lower().split())
        parent_norm = " ".join(ev['parent_cmdline'].lower().split())
        
        for cmd in command_strings:
            cmd_norm = " ".join(cmd.lower().split())
            if cmd_norm in cmdline_norm or cmd_norm in parent_norm:
                if ev['process_guid']:
                    known_guids[ev['process_guid']] = cmd
                all_extracted_record_ids.add(ev['record_id'])
                tree_mapping[ev['record_id']] = cmd
                break
                
    # 3. Phase 3: Loop to collect Child Events and inherit root commands
    changed = True
    while changed:
        changed = False
        for ev in parsed_events:
            if ev['process_guid'] and ev['process_guid'] not in known_guids:
                if ev['parent_process_guid'] in known_guids:
                    # It's a child! Inherit from parent
                    root_cmd = known_guids[ev['parent_process_guid']]
                    known_guids[ev['process_guid']] = root_cmd
                    all_extracted_record_ids.add(ev['record_id'])
                    tree_mapping[ev['record_id']] = root_cmd
                    changed = True

def export_all_logs():
    global all_extracted_record_ids
    if not all_extracted_record_ids:
        print("[-] No relevant logs to export to sigma_execution.evtx.")
        return False
        
    print(f"[*] Exporting {len(all_extracted_record_ids)} Sysmon events to sigma_execution.evtx...")
    sq_xml = '<QueryList><Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">'
    record_ids_list = list(all_extracted_record_ids)
    # Use individual <Select> nodes for each EventRecordID to avoid XPath complexity limits (wevtutil error 15001)
    for rid in record_ids_list:
        select_node = f'<Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventRecordID={rid})]]</Select>'
        sq_xml += select_node
    sq_xml += '</Query></QueryList>'
    
    temp_sq_file = "sigma_execution_query.xml"
    try:
        with open(temp_sq_file, "w", encoding='utf-8') as f:
            f.write(sq_xml)
            
        subprocess.run(['wevtutil', 'epl', temp_sq_file, 'sigma_execution.evtx', '/sq:true', '/ow:true'], check=True)
        print("[+] Successfully exported sigma_execution.evtx")
        return True
    except Exception as e:
        print(f"[!] Error exporting events: {e}")
        return False

def write_overall_stats():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir_path = os.path.join(script_dir, OUT_DIR)
    
    if not os.path.exists(out_dir_path):
        os.makedirs(out_dir_path)
        
    overall_path = os.path.join(out_dir_path, "Overall.csv")
    print(f"\n[*] Writing Overall.csv statistics to {overall_path}...")
    try:
        with open(overall_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Count"])
            writer.writerow(["Total Executed Commands", stats_total_executed])
            writer.writerow(["Total Failed Commands", stats_total_failed])
            writer.writerow(["Commands Bypassed Target Only", stats_bypass_target_only])
            writer.writerow(["Commands Bypassed All Rules", stats_bypass_all])
            writer.writerow(["Commands Captured by Target", stats_captured_by_target])
            writer.writerow([])
            writer.writerow(["Rule Title", "State"])
            for rule_title, state in rule_states.items():
                writer.writerow([rule_title, state])
        print("[+] Successfully wrote Overall.csv")
    except Exception as e:
        print(f"[!] Error writing Overall.csv: {e}")

    result_path = os.path.join(out_dir_path, "result.csv")
    print(f"\n[*] Writing result.csv statistics to {result_path}...")
    try:
        with open(result_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Rule Title", "State"])
            for rule_title, state in rule_states.items():
                writer.writerow([rule_title, state])
        print("[+] Successfully wrote result.csv")
    except Exception as e:
        print(f"[!] Error writing result.csv: {e}")

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

    global stats_total_executed, stats_total_failed
    curr_batch_length = execute_queue.qsize()
    
    expected_return_code = None
    
    for i in range(curr_batch_length):
        command_obj = execute_queue.get()
        if isinstance(command_obj, dict):
            command = command_obj.get('command', '')
            rule_title = command_obj.get('rule_title', 'unknown')
            is_original = command_obj.get('is_original', False)
        else:
            command = command_obj
            rule_title = 'unknown'
            is_original = False
        
        stats_total_executed += 1
        result = agent.execute_command(command)
        
        if is_original:
            expected_return_code = result.get('return_code') if isinstance(result, dict) else getattr(result, 'return_code', None)
        
        # Check for syntax errors in stderr
        has_syntax_error = False
        if result:
            actual_return_code = result.get('return_code') if isinstance(result, dict) else getattr(result, 'return_code', None)
            if actual_return_code != expected_return_code:
                has_syntax_error = True
                
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
                    'access is denied',
                    'invalid argument',
                    'invalid flag', 'invalid',
                    'invalid option',
                    'alias not found',
                    '/?','-?','-h','--help','/h','not a valid',
                    'syntax is incorrect', 'incorrect'
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
            start_time = result.get('start_time') if isinstance(result, dict) else getattr(result, 'start_time', None)
            execute_queue.put({'command': command, 'rule_title': rule_title, 'start_time': start_time})
            all_result.append(result)
        else:
            stats_total_failed += 1
            print(f"Removed commands: {command} (Rule: {rule_title})")
    
    return all_result


def zircolite_check(
    rules_dir='./windows_process_creation',
    events_file='sigma_execution.evtx',
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
ZIRCOLITE_CHECK_INTERVAL = 100  # Run Zircolite once every N seeds
def fuzzing_loop(mode='basic', target_count=5, max_attempts=50):
    seeds_processed = 0 
    pending_commands = []
    llm_call_counts = {} 
    
    print("[*] Fetching initial Sysmon Record ID...")
    current_start_record_id = get_latest_sysmon_record_id()
    print(f"[*] Starting from Record ID: {current_start_record_id}")
    
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

                if mode == 'llm_only':
                    print(f"[*] Querying LLM for {target_count} bypass commands for seed...")
                    mutated_commands = get_multiple_bypass_cmds_with_model(rule_filename, curr_seed, target_count)
                    if not mutated_commands:
                        print("[!] LLM failed to generate commands. Falling back to original seed.")
                        mutated_commands = [{"command": curr_seed, "technique": ["Unknown"]}]
                else:
                    raw_commands = fuzzing(curr_seed_obj, target_count=target_count, max_attempts=max_attempts)
                    mutated_commands = [{"command": c, "technique": ["token_mutation"]} for c in raw_commands]
                
                for cmd_dict in mutated_commands:
                    cmd_str = cmd_dict.get("command", "")
                    technique = cmd_dict.get("technique", ["Unknown"])
                    execute_queue.put({
                        'command': cmd_str, 
                        'rule_title': rule_title,
                        'is_original': cmd_str == curr_seed,
                        'technique': technique
                    })
                execute()
                seeds_processed += 1

                commands_added = 0
                # Drain execute_queue into pending_commands
                while not execute_queue.empty():
                    cmd_obj = execute_queue.get()
                    commands_added += 1
                    if isinstance(cmd_obj, dict):
                        pending_commands.append({
                            'command':       cmd_obj.get('command', ''),
                            'rule_title':    cmd_obj.get('rule_title', 'unknown'),
                            'rule_filename': rule_filename,
                            'start_time':    cmd_obj.get('start_time', None),
                            'technique':     cmd_obj.get('technique', ['Unknown'])
                        })
                    else:
                        pending_commands.append({
                            'command':       cmd_obj,
                            'rule_title':    'unknown',
                            'rule_filename': rule_filename,
                            'start_time':    None,
                            'technique':     ['Unknown']
                        })
                
                if commands_added == 0:
                    print(f"[!] No valid commands executed for seed: {curr_seed}. Writing to not_executed.csv")
                    with open(os.path.join(script_dir, OUT_DIR, "not_executed.csv"), "a", encoding="utf-8", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([rule_filename, curr_seed])

                # Only run Zircolite every ZIRCOLITE_CHECK_INTERVAL seeds
                if seeds_processed % ZIRCOLITE_CHECK_INTERVAL != 0:
                    remaining = ZIRCOLITE_CHECK_INTERVAL - (seeds_processed % ZIRCOLITE_CHECK_INTERVAL)
                    print(f"[*] Seed {seeds_processed}: {len(pending_commands)} commands pending Zircolite check "
                          f"({remaining} seeds until next check).")
                    continue

                print(f"[*] Reached {seeds_processed} seeds — running Zircolite check "
                      f"on {len(pending_commands)} accumulated commands...")
                #Waiting for Sysmon to logs all events....
                countdown_sleep(30, "Waiting for Sysmon to log all events")
                find_relevant_logs(pending_commands, current_start_record_id)
                
                if export_all_logs():
                    zircolite_check()
                else:
                    print("[!] No logs exported, skipping Zircolite check for this batch.")
                    # Ensure stale detections are not reused
                    if os.path.exists(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS)):
                        try:
                            os.remove(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS))
                        except Exception:
                            pass

                # Reset start_record_id, clear mapped events, and empty pending commands for the next batch
                current_start_record_id = get_latest_sysmon_record_id()
                all_extracted_record_ids.clear()
                tree_mapping.clear()
                
                print(f"[*] Resetting start Record ID for next batch: {current_start_record_id}")


                # Build a mapping of commands to the alert rules that detected them.
                command_rule_map = {}  # {command: [{title, id}, ...]}

                try:
                    with open(os.path.join(script_dir, ZIRCOLITE_DETECTED_EVENTS), "r", encoding='utf-8', errors='replace') as f:
                        rules_triggered = json.load(f)
                except FileNotFoundError:
                    rules_triggered = []

                for rule in rules_triggered:
                    rule_title_iter = rule.get("title", "unknown")
                    rule_id    = rule.get("id", "unknown")
                    matches    = rule.get("matches", [])
                    for match in matches:
                        record_id = str(match.get("EventRecordID", ""))
                        if not record_id:
                            record_id = str(match.get("System.EventRecordID", ""))
                            
                        if record_id and record_id in tree_mapping:
                            root_cmd = tree_mapping[record_id]
                            entry = command_rule_map.setdefault(root_cmd, [])
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
                csv_bypass_target_rows = []
                
                for cmd_obj in pending_commands:
                    curr_command  = cmd_obj['command']
                    cmd_rule_title    = cmd_obj['rule_title']
                    cmd_rule_filename = cmd_obj['rule_filename']
                    cmd_technique     = cmd_obj.get('technique', ['Unknown'])
                    
                    # Find all rules this command triggered
                    all_triggered_rules = []
                    
                    if curr_command in command_rule_map:
                        all_triggered_rules.extend(command_rule_map[curr_command])
                    
                    triggered_any = len(all_triggered_rules) > 0
                    triggered_target = any(e['title'] == cmd_rule_title for e in all_triggered_rules)
                    
                    global stats_bypass_all, stats_bypass_target_only, stats_captured_by_target
                    
                    cmd_state = ""
                    if not triggered_any:
                        cmd_state = "BYPASS_ALL"
                        stats_bypass_all += 1
                    elif triggered_any and not triggered_target:
                        cmd_state = "BYPASS_ONE"
                        stats_bypass_target_only += 1
                    else:
                        cmd_state = "CAPTURED"
                        stats_captured_by_target += 1
                        
                    # Update rule state map
                    # State Priority: BYPASS_ALL > BYPASS_ONE > CAPTURED
                    current_rule_state = rule_states.get(cmd_rule_title, "CAPTURED")
                    if cmd_state == "BYPASS_ALL":
                        rule_states[cmd_rule_title] = "BYPASS_ALL"
                    elif cmd_state == "BYPASS_ONE" and current_rule_state != "BYPASS_ALL":
                        rule_states[cmd_rule_title] = "BYPASS_ONE"
                    elif cmd_state == "CAPTURED" and current_rule_state not in ["BYPASS_ALL", "BYPASS_ONE"]:
                        rule_states[cmd_rule_title] = "CAPTURED"
                        
                    captured = triggered_target
                    matched_entries = [e for e in all_triggered_rules if e['title'] == cmd_rule_title]
                    
                    if captured:
                        print(f"[LOG] Captured command {curr_command} (Rule: {cmd_rule_title})")
                        captured_by_rule.setdefault(cmd_rule_filename, []).append(curr_command)
                    elif cmd_state == "BYPASS_ONE":
                        bypassed_by_rule.setdefault(cmd_rule_filename, []).append(curr_command)
                        alert_titles = ';'.join(e['title'] for e in all_triggered_rules)
                        alert_ids    = ';'.join(e['id']    for e in all_triggered_rules)
                        csv_bypass_target_rows.append({
                            'rule_filename':  cmd_rule_filename,
                            'rule_name':      cmd_rule_title,
                            'commandline':    curr_command,
                            'technique':      cmd_technique,
                            'alert_rules':    alert_titles,
                            'matched_rule_id': alert_ids,
                        })
                    elif cmd_state == "BYPASS_ALL":
                        bypassed_by_rule.setdefault(cmd_rule_filename, []).append(curr_command)
                        csv_bypass_rows.append({
                            'rule_filename': cmd_rule_filename,
                            'rule_name':     cmd_rule_title,
                            'commandline':   curr_command,
                            'technique':     cmd_technique
                        })

                # Clear staging list now that all commands have been classified
                pending_commands.clear()

                out_dir_path = os.path.join(script_dir, OUT_DIR)
                if not os.path.exists(out_dir_path):
                    os.makedirs(out_dir_path)

                # ----------------------------------------------------------------
                # Write CSV logs
                # ----------------------------------------------------------------
                bypass_csv_path   = os.path.join(out_dir_path, 'commandlines_pass_bypass.csv')
                bypass_target_csv_path = os.path.join(out_dir_path, 'command_bypass_target.csv')

                bypass_fields   = ['rule_filename', 'rule_name', 'commandline', 'technique']
                bypass_target_fields = ['rule_filename', 'rule_name', 'commandline', 'technique', 'alert_rules', 'matched_rule_id']

                for csv_path, fields, rows, label in [
                    (bypass_csv_path,   bypass_fields,   csv_bypass_rows,   'bypass_all'),
                    (bypass_target_csv_path, bypass_target_fields, csv_bypass_target_rows, 'bypass_target_caught_by_others'),
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
                #all_seen_rules = set(bypassed_by_rule) | set(captured_by_rule)
                #for r_filename in all_seen_rules:
                    #if r_filename not in bypassed_by_rule:
                        # Fetch the current call count for this specific rule
                        #current_llm_count = llm_call_counts.get(r_filename, 0)
                        
                        #if current_llm_count < 5:
                            #captured_cmds = captured_by_rule.get(r_filename, [])
                            #print(f"[*] No bypass found for '{r_filename}' — asking LLM for new candidates... (Attempt {current_llm_count + 1}/5)")
                            #new_command = get_potential_bypass_cmd_with_model(r_filename, captured_cmds)
                            #seed_queue.put({"command": new_command, "rule_filename": r_filename})
                            
                            # Increment the counter
                            #llm_call_counts[r_filename] = current_llm_count + 1
                        #else:
                            #print(f"[*] Max LLM attempts (5) reached for '{r_filename}'. Skipping LLM call.")
                    #else:
                        #print(f"[*] Bypass found for '{r_filename}' — skipping LLM call.")
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
        export_all_logs()
        write_overall_stats()
    except Exception as e:
        print(f"[!] Critical Error escaping inner fuzzing loop: {e}")
        traceback.print_exc()
        export_all_logs()
        write_overall_stats()

def main():
    parser = argparse.ArgumentParser(description="Fuzz command seeds using token-based mutations.")
    parser.add_argument('--seeds-dir', default=SEEDS_DIR, help=f"Directory containing seed files (default: {SEEDS_DIR})")
    parser.add_argument('--out-dir', default=OUT_DIR, help=f"Directory for output files (default: {OUT_DIR})")
    parser.add_argument('--target-count', type=int, default=5, help="Number of mutations per seed (default: 5)")
    parser.add_argument('--max-attempts', type=int, default=50, help="Max attempts to generate unique mutations (default: 50)")
    parser.add_argument('--mode', choices=['basic', 'llm_only'], default='basic', help="Fuzzing mode: 'basic' (token mutation) or 'llm_only' (LLM generation)")
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

    # Look for .json, .txt, .csv, and .tsv seed files
    seed_files_json = [f for f in os.listdir(seeds_dir_path) if f.endswith(".json")]
    seed_files_txt  = [f for f in os.listdir(seeds_dir_path) if f.endswith(".txt")]
    seed_files_csv  = [f for f in os.listdir(seeds_dir_path) if f.endswith(".csv")]
    seed_files_tsv  = [f for f in os.listdir(seeds_dir_path) if f.endswith(".tsv")]

    if not seed_files_json and not seed_files_txt and not seed_files_csv and not seed_files_tsv:
        print(f"[!] No .json, .txt, .csv, or .tsv files found in '{SEEDS_DIR}'.")
        return

    print(f"[*] Found {len(seed_files_json)} JSON, {len(seed_files_txt)} TXT, "
          f"{len(seed_files_csv)} CSV, and {len(seed_files_tsv)} TSV seed files. Starting batch processing...")
    
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

    # Process CSV and TSV files — expected columns: target_rule, commandline
    CSV_RULE_COL    = "target_rule"
    CSV_CMD_COL     = "commandline"

    for filename in seed_files_csv + seed_files_tsv:
        input_path = os.path.join(seeds_dir_path, filename)
        is_tsv = filename.lower().endswith(".tsv")
        print(f"\n---> Processing {'TSV' if is_tsv else 'CSV'}: {filename}")
        added = 0
        try:
            with open(input_path, 'r', encoding='utf-8-sig') as f: 
                reader = csv.DictReader(f, delimiter='\t' if is_tsv else ',')

                # Validate that the required columns are present
                if reader.fieldnames is None:
                    print(f"[!] {'TSV' if is_tsv else 'CSV'} file '{filename}' appears to be empty — skipping.")
                    continue

                missing = {CSV_RULE_COL, CSV_CMD_COL} - {c.strip() for c in reader.fieldnames}
                if missing:
                    print(f"[!] {'TSV' if is_tsv else 'CSV'} file '{filename}' is missing required column(s): "
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
                    #print(f"  Added seed: {command} (Rule: {rule_filename})")
                    added += 1

            print(f"[+] {added} seed(s) loaded from '{filename}'.")

        except Exception as e:
            print(f"[!] Error reading CSV file {filename}: {e}")
            continue

    #FUZZING LOOP
    fuzzing_loop(args.mode, args.target_count, args.max_attempts)

    export_all_logs()
    write_overall_stats()
    print(f"\n[*] All done! Check the '{OUT_DIR}' folder.")


if __name__ == "__main__":
    main()