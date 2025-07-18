import re
from collections import Counter
from .load_data import load_command_resources

valid_commands, similarity_matrix, purpose_lookup, _ = load_command_resources()

OPERATOR_PATTERN = r'(\|\||&&|\||;|>|>>)'
OPERATORS = {'|', '||', '&&', ';', '>', '>>'}

def classify_argument(arg):
    """
    Classifies a command-line argument into semantic types (e.g., COMMAND, FILE, FLAG, IP, etc.).

    Args:
        arg (str): A single token/argument from a command line.

    Returns:
        dict: A dictionary with keys 'type' and 'value', where 'type' is the semantic category.
    """

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
    """
    Converts a raw shell command line into a semantically abstracted representation.

    - Tokenizes by operators and whitespace
    - Classifies each argument
    - Handles `echo` payloads with a simplified abstraction

    Args:
        cmd_line (str): Raw shell command line.

    Returns:
        str: Abstracted command line string, e.g., "COMMAND FILE FLAG".
    """

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
    """
    Groups flags with their corresponding commands or arguments.

    Assumes the command has been abstracted (via `abstract_command_line_substitution`).

    Args:
        abstract_cmd (str): An abstracted command string.

    Returns:
        list: A list of grouped token strings, e.g., ["COMMAND -f", "FILE"].
    """

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
    """
    Splits a shell command string by common shell operators like `|`, `&&`, `;`, etc.

    Args:
        cmd (str): Raw shell command.

    Returns:
        list: List of command segments and operators in original order.
    """

    return re.split(r'(\|\||&&|\||;|>|>>)', cmd)

def is_pure_string(cmd):
    """
    Checks whether a given command line consists only of a single string payload (e.g., `echo "hi"`).

    Args:
        cmd (str): Raw command line string.

    Returns:
        bool: True if the command is a single string abstraction, False otherwise.
    """

    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return abs_cmd.startswith("STRING(") and " " not in abs_cmd

def is_real_command(cmd):
    """
    Determines if the command is considered meaningful (i.e., not just a string payload).

    Uses the abstraction to detect commands that carry operational intent.

    Args:
        cmd (str): Raw command line.

    Returns:
        bool: True if the command is operationally relevant, False if it's just a string.
    """

    if not cmd or not cmd.strip():
        return False
    abs_cmd = abstract_command_line_substitution(cmd).strip()
    return not (abs_cmd.startswith("STRING(") and " " not in abs_cmd)

def classify_purpose_from_lookup(commands):
    """
    Determines the behavioral purpose(s) of a list of commands using a preloaded lookup table.

    Tries to match each command to known patterns, falling back to "Execution" or "Unknown".

    Args:
        commands (list): List of raw command-line strings.

    Returns:
        str: A string summarizing one or more inferred purposes (e.g., "Reconnaissance + Execution").
    """

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

