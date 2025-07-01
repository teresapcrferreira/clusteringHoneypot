import re
from collections import Counter
from .load_data import load_command_resources

valid_commands, similarity_matrix, purpose_lookup, _ = load_command_resources()

OPERATOR_PATTERN = r'(\|\||&&|\||;|>|>>)'
OPERATORS = {'|', '||', '&&', ';', '>', '>>'}

def classify_argument(arg):
    if arg in valid_commands or arg in ('busybox', 'which'):
        return {'type': arg, 'value': arg}
    if arg.startswith("./"):
        return {'type': 'FILE_SCRIPT' if arg.endswith('.sh') else 'FILE_EXECUTION', 'value': arg}
    if arg in OPERATORS:
        return {'type': 'OPERATOR', 'value': arg}
    if re.match(r'^https://', arg, re.IGNORECASE):
        return {'type': 'SECURE_URL', 'value': arg}
    if re.match(r'^http://', arg, re.IGNORECASE):
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
    parts = re.split(OPERATOR_PATTERN, cmd_line)
    new_parts = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if part in OPERATORS:
            new_parts.append(part)
        else:
            tokens = part.split()
            if tokens and tokens[0] == "echo":
                payload = " ".join(tokens[1:]).strip('"\'')
                new_parts.append("echo STRING({})".format(len(payload)))
            else:
                types = [classify_argument(t)['type'] for t in tokens]
                new_parts.append(" ".join(types))
    return " ".join(new_parts)

def group_commands_and_flags(abstract_cmd):
    tokens = abstract_cmd.strip().split()
    grouped = []
    for i, token in enumerate(tokens):
        if classify_argument(token)['type'] == 'OPERATOR':
            continue
        if token.startswith('-') and i > 0:
            grouped[-1] = f"{grouped[-1]} {token}"
        else:
            grouped.append(token)
    return grouped

def split_by_operators(cmd):
    return re.split(r'(\|\||&&|\||;)', cmd)

def is_pure_string(cmd):
    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return abs_cmd.startswith("STRING(") and " " not in abs_cmd

def is_real_command(cmd):
    if not cmd or not cmd.strip():
        return False
    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return not (abs_cmd.startswith("STRING(") and " " not in abs_cmd)

def classify_purpose_from_lookup(commands):
    purpose_counts = Counter()

    for cmd in commands:
        if not cmd or not cmd.strip():
            continue

        sub_cmds = re.split(OPERATOR_PATTERN, cmd)

        for sub in sub_cmds:
            sub = sub.strip()
            if not sub or sub in OPERATORS:
                continue

            tokens = sub.split()
            if not tokens:
                continue

            full_key = " ".join(tokens)
            base_key = tokens[0]

            if full_key in purpose_lookup:
                purpose = purpose_lookup[full_key]
            elif base_key in purpose_lookup:
                purpose = purpose_lookup[base_key]
            elif base_key.startswith("./"):
                purpose = "Execution"
            else:
                purpose = "Unknown"

            purpose_counts[purpose] += 1

    purposes = [p for p in purpose_counts if p != "Unknown"]
    return " + ".join(sorted(set(purposes))) if purposes else "Unknown"

