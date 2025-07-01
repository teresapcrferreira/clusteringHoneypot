from .preprocessing import is_pure_string, group_commands_and_flags
from .load_data import load_command_resources

_, similarity_matrix, _ = load_command_resources()

__all__ = ["geometric_distance", "distance_func"]

SIMILARITY_THRESHOLD = 1e-9

def geometric_distance(cmd1, cmd2, sim_matrix):
    if is_pure_string(cmd1) or is_pure_string(cmd2):
        return 1.0

    units1 = group_commands_and_flags(cmd1.strip())
    units2 = group_commands_and_flags(cmd2.strip())
    n = min(len(units1), len(units2))
    sims = []

    for u1, u2 in zip(units1[:n], units2[:n]):
        if u1.isupper() or u2.isupper() or '(' in u1 or '(' in u2:
            continue
        sims.append(sim_matrix.get(u1, {}).get(u2, 0.0))

    if not sims:
        return 1.0

    product = 1.0
    for s in sims:
        product *= max(s, SIMILARITY_THRESHOLD)

    geometric_mean = product ** (1.0 / len(sims))
    return 1.0 - geometric_mean

def distance_func():
    return lambda x, y: geometric_distance(x, y, similarity_matrix)
