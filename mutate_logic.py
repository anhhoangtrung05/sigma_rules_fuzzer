import random

char_mapping = {
    'a': 'ᵃ', 'b': 'ᵇ', 'c': 'ᶜ', 'd': 'ᵈ', 'e': 'ᵉ', 'f': 'ᶠ',
    'g': 'ᵍ', 'h': 'ʰ', 'i': 'ⁱ', 'j': 'ʲ', 'k': 'ᵏ', 'l': 'ˡ',
    'm': 'ᵐ', 'n': 'ⁿ', 'o': 'ᵒ', 'p': 'ᵖ', 'q': 'ᵍ', 'r': 'ʳ',
    's': 'ˢ', 't': 'ᵗ', 'u': 'ᵘ', 'v': 'ᵛ', 'w': 'ʷ', 'x': 'ˣ',
    'y': 'ʸ', 'z': 'ᶻ'
}

def randomize_case(token, token_type):
    """
    Randomize the case of a token
    """
    if token_type == 'url':
        pos = token.find("://")
        mutated_part = token[:pos]
        keep_part = token[pos:]
        token = mutated_part + keep_part
        return token

    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in token)

def should_randomize_case(token_type, token):
    """
    Determine if a token should be case-mutated 
    """
    case_mutable_types = ['executable_name', 'flag', 'ps_var', 'env', 'operator', 'url', 'subcommand', 'literal']
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
    prefix = flag[0] if flag[0] in ['-', '/'] else ''
    rand = random.randint(0, 1)
    if rand == 0:
        if flag[0] == '-':
            prefix = '/'
        elif flag[0] == '/':
            prefix = '-'

    rest = flag[1:]
    if rest[0] != "\"":
        return f'{prefix}"{rest}"'
        #do not wrap tons of quotes
    return f'{prefix}{rest}'

def replace_with_spacing_modifier(char):
    """
    Replace a character with a spacing modifier letter (Unicode 0x02B0-0x02FF range).
    Returns original character followed by a random spacing modifier.
    """
    return char_mapping.get(char, char)


def obfuscate_string(flag):
    """
    Obfuscate a subcommand token/a string by randomly joining with carets (^) or wrapping random characters with quotes
    """
    forbidden_next_chars = ['n', 'r', 't', 'a', 'b', 'f', 'v', '0', '"', "'", '$']

    if random.random() > 0.5:
        # Join with carets
        return "^".join(flag)
    else:
        # Wrap random characters with double quotes
        result = []
        backtick = False
        length = len(flag)
        for i in range(0, length):

            char = flag[i]
            #last character and backtick not closed yet
            if backtick == True and i == length - 1:
                result.append(f"{char}`")
                backtick = False
                continue
            
            rand = random.randint(0, 3)
            match rand:
                case 0:
                    result.append(f'"{char}"')
                case 1:
                    result.append(replace_with_spacing_modifier(char))
                case 2:
                    if char not in forbidden_next_chars and i < (length - 1) and backtick == False:
                        result.append(f"`{char}")
                        backtick = True
                    elif backtick == True: #close backtick
                        result.append(f"{char}`")
                        backtick = False
                    else:
                        result.append(char)
                case _:
                    result.append(char)
        
        
        return ''.join(result)

