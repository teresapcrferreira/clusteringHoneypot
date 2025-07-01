import pandas as pd

def load_command_resources():
    commands_df = pd.read_csv("databases/commands_cleaned.csv")
    valid_commands = set(commands_df["Command"].str.strip().unique())

    similarity_matrix = pd.read_csv("databases/UpdatedSimilarity.csv", index_col=0)

    purpose_df = pd.read_csv("databases/UpdatedCommandDB.csv")
    purpose_lookup = dict(zip(
        purpose_df["label"].str.strip(),
        purpose_df["simplified_purpose"].fillna("Unclassified")
    ))

    return valid_commands, similarity_matrix, purpose_lookup
