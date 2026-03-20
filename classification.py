import argparse
import shlex
import re

PLACEHOLDER_RE = re.compile(r'#?\{([A-Za-z0-9_.:-]+)\}')
ENV_VAR_RE = re.compile(r'^%.+%$')
PS_VAR_RE = re.compile(r'^\$[a-zA-Z0-9_:]+$')
FLAG_RE = re.compile(r'^\^?[/-].+')
OPERATOR_RE = re.compile(r'^[&|><!]+$')
URL_RE = re.compile(r'^[a-zA-Z0-9-]{2,20}://')
IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
PATH_RE = re.compile(r'.*[\\]+.*')
EXT_RE = re.compile(r'\.([a-zA-Z0-9]{2,5})$')
CMDLET_RE = re.compile(r'^[a-zA-Z]+-[a-zA-Z]+$')

CMD_RE = re.compile(
    r'^(?:'
    r'(?:[a-zA-Z]:|\\\\).*?\.(?:exe|bat|ps1|cmd|vbs)|'  # Absolute path with extension (e.g., C:\Tools\ncat.exe)
    r'[a-zA-Z0-9_.-]+\.(?:exe|bat|ps1|cmd|vbs)|'       # Executable with extension (e.g., cmd.exe)
    r'cmd|powershell|pwsh|bash|wsl|wmic'               # Known executables often used without extensions
    r')'
    r'\s+[^ \t\n\r].*$',                               # Must have at least one space followed by an argument
    re.IGNORECASE
)

# Shell Identification
SHELL_RE = re.compile(r'(?:^|[\\/])(powershell|pwsh|cmd|bash|wsl)(?:\.exe)?$', re.IGNORECASE)

EXEC_EXTS = {'exe', 'dll', 'ps1', 'vbs', 'bat', 'cpl', 'scr', 'inf', 'sct'}
SUBCOMMANDS = {'exec', 'create', 'call', 'get', 'delete', 'insert', 'add', 'set', 'list', 'start', 'stop'}

def try_parse_with_argparse(executable, command, dict_list):
    """
    Attempt to parse the command using argparse for better token identification.
    Uses argument_dict (for arguments with values) and switch_dict (for boolean flags).
    
    Args:
        executable: The executable name (e.g., 'certutil.exe')
        command: The full command string to parse
        dict_list: Dict containing 'argument_dict' and 'switch_dict'
                  - Keys are flags, values are aliases
    
    Returns:
        Dict with parsed arguments and unknown tokens, or None on failure
    """
    try:
        # Parse command into tokens
        tokens = shlex.split(command)
        
        parser = argparse.ArgumentParser(prog=executable, add_help=False)
        
        argument_dict, switch_dict = dict_list

        for flag, alias in argument_dict.items():
            parser.add_argument(flag, nargs='?', default=None, help=f'Alias: {alias}')
            if alias and alias != flag:
                parser.add_argument(alias, nargs='?', default=None, help=f'Alias for {flag}')
        
        for flag, alias in switch_dict.items():
            parser.add_argument(flag, action='store_true', help=f'Alias: {alias}')
            if alias and alias != flag:
                parser.add_argument(alias, action='store_true', help=f'Alias for {flag}')
        
        # Parse the remaining tokens
        args, unknown = parser.parse_known_args(tokens)
        
        return {
            'executable': executable,
            'parsed_args': vars(args),
            'unknown': unknown,
            'tokens': tokens
        }
    except Exception as e:
        return None

def classify_token(token):
    token = token.strip().strip('"\'')
    if not token: return None, None
    

    if PLACEHOLDER_RE.search(token): return 'placeholder'

    if CMD_RE.match(token): return 'cmd'

    if SHELL_RE.search(token):
        return 'executable_name'

    if PS_VAR_RE.match(token): return 'ps_var'
    if CMDLET_RE.match(token): return 'executable_name'


    if ENV_VAR_RE.match(token): return 'env'
    if FLAG_RE.match(token): return 'flag'
    if OPERATOR_RE.match(token): return 'operator'
    if token.lower() in SUBCOMMANDS: return 'subcommand'
    if URL_RE.search(token): return 'url'
    if IP_RE.match(token): return 'ip'
    
    if PATH_RE.search(token):
        ext_match = EXT_RE.search(token)
        if ext_match and ext_match.group(1).lower() in EXEC_EXTS: 
            return 'executable_name'
        return 'path'
    
    ext_match = EXT_RE.search(token)
    if ext_match and ext_match.group(1).lower() in EXEC_EXTS: 
        return 'executable_name'
    
    return 'literal'
