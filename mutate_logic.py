import random

def randomize_case(token, token_type):
    """
    Randomize the case of a token
    """

    #mutate url scheme
    if token_type == 'url':
        pos = token.find("://")
        mutated_part = token[:pos]
        keep_part = token[pos:]
        mutated = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in mutated_part)
        token = mutated + keep_part
        return token

    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in token)

def should_randomize_case(token_type, token):
    """
    Determine if a token should be case-mutated 
    """
    case_mutable_types = ['executable_name', 'flag', 'ps_var', 'env', 'operator', 'url', 'subcommand']
   
    if token and (token[0].isalpha() or token[0] in ['-', '/']):
        return token_type in case_mutable_types
    return False

def obfuscate_flag(flag):
    """
    Obfuscate a single flag by adding quotes around the flag name.
    """
    if not flag:
        return flag
    
    # Handle flags starting with - or /
    if flag[0] in ['-', '/']:
        prefix = flag[0]
        rest = flag[1:]
        return f'{prefix}"{rest}"'
    
    return flag


def add_noise_flags(tokens, noise_dict):
    """
    Add benign switch flags
    """
    if not tokens or not noise_dict or random.random() > 0.3:  # 30% probability
        return tokens
    
    noise = random.choice(list(noise_dict.keys()))
    
    # Insert noise flag
    new_tokens = [tokens[0]]
    if len(noise) > 0:
        new_tokens.append(noise)
    new_tokens.extend(tokens[1:])
    return new_tokens

def obfuscate_executable(executable):
    """
    Obfuscate executable names to evade SIEM detection.
    """
    # 4 obfuscation methods applicable to all executables
    obfuscation_methods = [
        #lambda x: '^'.join(x),  # c^a^l^c or p^o^w^e^r^s^h^e^l^l
        #lambda x: f'%COMSPEC% /c "{x}"',  # Wrap in cmd /c
        lambda x: randomize_case(x, "executable"),  # CaLc or PoWeRsHeLL
        lambda x: f'%SystemRoot%\\System32\\{x}',  # Add System32 path
    ]
    
    method = random.choice(obfuscation_methods)
    return method(executable)

