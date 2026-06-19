import os
import sys

def get_rule_content(rule_filename: str) -> str:
    """
    Returns the content of a rule file inside the windows_process_creation folder.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_dir = os.path.join(base_dir, "windows_process_creation")
    rule_path = os.path.join(rule_dir, rule_filename)
    
    # Check if file exists, if not, try appending .yml
    if not os.path.exists(rule_path):
        if not rule_filename.endswith('.yml') and os.path.exists(rule_path + '.yml'):
            rule_path += '.yml'
        else:
            return f"Error: Rule '{rule_filename}' not found in {rule_dir}."
            
    try:
        with open(rule_path, 'r', encoding='utf-8') as f:
            content = f.read()
        prompt = f"""You are a SIEM detection engineering assistant with expert knowledge of Sigma rules,
Windows process creation logs, and command-line parsing.
Please write down all instances of the commands. but meaningful command for the attacker to trigger
this SIEM rule
Sigma_rule:
{content}
Please note that the binaries are not available on Windows.
You can use the default paths of the Atomic Red Team tool.
You should read the references (use URL context).
If the rules require finding a parent image/image that is not supposed to run commands directly (hints of human/application exploits that lead to RCE), use the "copy from cmd.exe" simulation technique.
Each command that you provide should include all stages from initialization (if there is) to execution
The output only displays the command lines; it doesn't generate anything else"""
        with open("prompt.txt", "w") as f:
            f.write(prompt)
        return "done"
    except Exception as e:
        return f"Error reading file {rule_path}: {e}"

if __name__ == "__main__":
    content = get_rule_content("proc_creation_win_vscode_child_processes_anomalies")
    print(content)
