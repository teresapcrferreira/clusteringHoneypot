import re
from collections import Counter
from .load_data import load_command_resources

valid_commands, similarity_matrix, purpose_lookup = load_command_resources()

__all__ = [
    "classify_argument",
    "abstract_command_line_substitution",
    "group_commands_and_flags",
    "split_by_operators",
    "is_pure_string",
    "is_real_command",
    "classify_purpose_from_lookup",
]

def classify_argument(arg):
    if arg in valid_commands or arg in ('busybox', 'which'):
        return {'type': arg, 'value': arg}
    if arg.startswith("./"):
        return {'type': 'FILE_SCRIPT' if arg.endswith('.sh') else 'FILE_EXECUTION', 'value': arg}
    if arg in ('>', '>>', '&&', ';', '||', '|'):
        return {'type': 'OPERATOR', 'value': arg}
    if re.match(r'^https://', arg, flags=re.IGNORECASE):
        return {'type': 'SECURE_URL', 'value': arg}
    elif re.match(r'^http://', arg, flags=re.IGNORECASE):
        return {'type': 'URL', 'value': arg}
    if re.match(r'^\b\d{1,3}(?:\.\d{1,3}){3}\b$', arg):
        return {'type': 'IP', 'value': arg}
    if re.match(r'\\x[0-9a-fA-F]{2}', arg):
        return {'type': 'HEX', 'value': arg}
    if arg.startswith('/'):
        return {'type': 'FILE_SCRIPT' if arg.endswith('.sh') else 'FILE' if '.' in arg.split('/')[-1] else 'PATH', 'value': arg}
    if arg.startswith('-'):
        return {'type': arg, 'value': arg}
    if '.' in arg:
        return {'type': 'FILE', 'value': arg}
    return {'type': 'STRING', 'value': arg}

def abstract_command_line_substitution(cmd_line):
    pattern = r'(\|\||&&|\||;|>|>>)'
    parts = re.split(pattern, cmd_line)
    new_parts = []

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if part in ('||', '&&', '|', ';', '>', '>>'):
            new_parts.append(part)
        else:
            tokens = part.split()
            new_tokens = []

            if tokens and tokens[0] == "echo":
                # Join everything after echo as one string
                payload = " ".join(tokens[1:])
                payload_clean = payload.strip('"\'')  # remove surrounding quotes
                new_tokens.append("echo")
                new_tokens.append(f'STRING({len(payload_clean)})')
            else:
                new_tokens = [classify_argument(t)['type'] for t in tokens]

            new_parts.append(" ".join(new_tokens))

    return " ".join(new_parts)

def group_commands_and_flags(abstract_cmd):
    tokens = abstract_cmd.strip().split()
    grouped = []
    skip_next = False
    for i, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        classification = classify_argument(token)
        if classification['type'] == 'OPERATOR':
            continue
        if token.startswith('-') and i > 0:
            prev_token = grouped.pop() if grouped else ''
            grouped.append(f"{prev_token} {token}")
            continue
        grouped.append(token)
    return grouped

def split_by_operators(cmd):
    return re.split(r'(\|\||&&|\||;)', cmd)

def is_pure_string(cmd):
    # abstract it and see if it’s exactly one token that starts with STRING(
    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return abs_cmd.startswith("STRING(") and " " not in abs_cmd

def is_real_command(cmd):
    """
    Return False if cmd is empty/whitespace or its abstract form
    is exactly a lone STRING(...) token.
    """
    if not cmd or not cmd.strip():
        return False

    abs_cmd = abstract_command_line_substitution(cmd).strip()
    # a single token that starts with STRING( and has no spaces is not a real command
    if abs_cmd.startswith("STRING(") and " " not in abs_cmd:
        return False

    return True

def classify_purpose_from_lookup(commands):
    """
    Determine the combined purposes of a command sequence.
    The purposes will be ordered alphabetically.
    """

    purpose_counts = Counter()

    for cmd in commands:
        if not cmd or not cmd.strip():
            continue

        # Split the command by logical/pipe operators to analyze parts
        sub_cmds = re.split(r'\s*(\|\||&&|\||;|>|>>)\s*', cmd)
        for sub in sub_cmds:
            sub = sub.strip()
            if not sub or sub in {'|', '||', '&&', ';', '>', '>>'}:
                continue

            tokens = sub.split()
            if not tokens:
                continue

            key = tokens[0]
            if key.startswith("./"):
                purpose = "Execution"
            else:
                purpose = purpose_lookup.get(key, "Unknown")
            purpose_counts[purpose] += 1

    if not purpose_counts:
        return "Unknown"

    # Collect unique purposes that are not "Unknown"
    purposes = [purpose for purpose in purpose_counts if purpose != "Unknown"]
    if not purposes:
        return "Unknown"

    # Sort the purposes alphabetically
    sorted_purposes = sorted(set(purposes))

    return " + ".join(sorted_purposes)
