# ------------------------------------------------------------
# 🧪 process_and_prepare_dataset.py
# Dataset Cleaner + Feature Engineer for IDS Model Training
# Intel Unnati IDS | Authors : Arjun, Nimish and Shaurya | Version: 1.0
# ------------------------------------------------------------

import pandas as pd
import numpy as np

# ------------------------------------------------------------
# 📂 Load Raw CSVs
# ------------------------------------------------------------

attack_df = pd.read_csv("csv/attack_raw.csv")
normal_df = pd.read_csv("csv/normal_raw.csv")

# 🧹 Fill missing values with 0
attack_df.fillna(0, inplace=True)
normal_df.fillna(0, inplace=True)

# 🏷️ Add binary labels
attack_df["label"] = 1
normal_df["label"] = 0

# ------------------------------------------------------------
# 🔻 Downsample (to balance dataset)
# ------------------------------------------------------------

# Cap normal traffic to 100K rows
normal_df = normal_df.sample(n=100000, random_state=42)

# Cap attacks to 100K rows max
if len(attack_df) > 100000:
    attack_df = attack_df.sample(n=100000, random_state=42)

# ------------------------------------------------------------
# 🧠 Smart Feature Engineering
# ------------------------------------------------------------

# Helper: Convert IP string to integer
def ip_to_int(ip):
    try:
        return int.from_bytes(bytes(map(int, str(ip).split("."))), "big")
    except:
        return 0

# Convert IP columns
for col in ["ip.src", "ip.dst"]:
    attack_df[col] = attack_df[col].apply(ip_to_int)
    normal_df[col] = normal_df[col].apply(ip_to_int)

# Convert TCP flags (e.g., "0x12" → 18)
for df in [attack_df, normal_df]:
    df["tcp.flags"] = df["tcp.flags"].apply(
        lambda x: int(str(x), 16) if str(x).startswith("0x") else int(float(x))
    )

# Add engineered features
for df in [attack_df, normal_df]:
    df["is_well_known_port"] = (df["tcp.dstport"] < 1024).astype(int)
    df["port_diff"] = abs(df["tcp.srcport"] - df["tcp.dstport"])
    df["tcp_flag_score"] = df["tcp.flags"] / (df["frame.len"] + 1)
    df["proto_complexity"] = (df["ip.proto"] > 100).astype(int)
    df["payload_size_est"] = df["udp.length"] + df["frame.len"]

# ------------------------------------------------------------
# 🧪 Final Combined Dataset
# ------------------------------------------------------------

final_df = pd.concat([attack_df, normal_df])
final_df.fillna(0, inplace=True)

# ------------------------------------------------------------
# 💾 Save Output
# ------------------------------------------------------------

final_df.to_csv("csv/final_processed.csv", index=False)
print("✅ Dataset ready: csv/final_processed.csv")
