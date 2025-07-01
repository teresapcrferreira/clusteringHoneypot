from .preprocessing import is_pure_string, group_commands_and_flags
from .load_data import load_command_resources

_, similarity_matrix, _ = load_command_resources()

__all__ = ["all_similarities", "geometric_mean", "geometric_distance", "distance_func"]

def all_similarities(cmd1, cmd2, sim_matrix):
    if is_pure_string(cmd1) or is_pure_string(cmd2):
        return []
    units1 = group_commands_and_flags(cmd1.strip())
    units2 = group_commands_and_flags(cmd2.strip())
    n = min(len(units1), len(units2))
    sims = []
    for u1, u2 in zip(units1[:n], units2[:n]):
        if u1.isupper() or u2.isupper() or '(' in u1 or '(' in u2:
            continue
        sims.append(sim_matrix.get(u1, {}).get(u2, 0.0))
    return sims

def geometric_mean(sims):
    if not sims:
        return 0.0
    prod = 1.0
    for s in sims:
        prod *= max(s, 1e-9)
    return prod ** (1.0 / len(sims))

def geometric_distance(a, b, sim_matrix):
    sims = all_similarities(a, b, sim_matrix)
    sim = geometric_mean(sims)
    return 1.0 - sim

def distance_func():
    return lambda x, y: geometric_distance(x, y, similarity_matrix)