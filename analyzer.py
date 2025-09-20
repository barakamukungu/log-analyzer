import os
import re
from collections import Counter, defaultdict
from datetime import datetime

# Optional graphing
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Step 1: Read log file
def read_log(filepath):
    if not os.path.exists(filepath):
        print(f"Error: The file '{filepath}' was not found.")
        return []
    with open(filepath, 'r', encoding="utf-8") as f:
        lines = [line.rstrip('\n') for line in f]
    return lines

# Step 2: Count log levels
def count_log_levels(log_lines):
    counts = {"INFO": 0, "ERROR": 0, "WARNING": 0, "DEBUG": 0}
    for line in log_lines:
        for level in counts.keys():
            if level in line:
                counts[level] += 1
                break
    return counts

# Step 3: Extract IP counts
def extract_ip_counts(log_lines):
    ip_counts = Counter()
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    for line in log_lines:
        ips = re.findall(ip_pattern, line)
        for ip in ips:
            ip_counts[ip] += 1
    return ip_counts

# Step 4: Detect failed login attempts
def detect_failed_logins(log_lines):
    failed_logins = Counter()
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    for line in log_lines:
        if "Invalid password attempt" in line:
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                failed_logins[ip] += 1
    return failed_logins

# Step 5: Hourly summary by log level
def analyze_by_hour_and_level(log_lines):
    hourly_levels = defaultdict(Counter)
    time_pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
    for line in log_lines:
        match = re.match(time_pattern, line)
        if match:
            timestamp = match.group(0)
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            hour_str = dt.strftime("%Y-%m-%d %H:00")
            for level in ["INFO", "ERROR", "WARNING", "DEBUG"]:
                if level in line:
                    hourly_levels[hour_str][level] += 1
                    break
    return hourly_levels

# ASCII table for hourly summary
def print_hourly_table(hourly_levels):
    levels = ["INFO", "ERROR", "WARNING", "DEBUG"]
    header = f"{'Hour':<15} " + " ".join(f"{lvl:<8}" for lvl in levels)
    print("\nLog entries by hour and level (table view):")
    print(header)
    print("-" * len(header))
    for hour, level_counts in sorted(hourly_levels.items()):
        row = f"{hour:<15} " + " ".join(f"{level_counts.get(lvl, 0):<8}" for lvl in levels)
        print(row)

# Graph visualization
def plot_hourly_summary(hourly_levels):
    if not HAS_MATPLOTLIB:
        print("\nMatplotlib not installed. Cannot plot graph.")
        return
    hours = sorted(hourly_levels.keys())
    levels = ["INFO", "ERROR", "WARNING", "DEBUG"]
    data = {level: [hourly_levels[hour].get(level, 0) for hour in hours] for level in levels}

    fig, ax = plt.subplots(figsize=(10,6))
    width = 0.2
    x = range(len(hours))
    for i, level in enumerate(levels):
        ax.bar([pos + i*width for pos in x], data[level], width=width, label=level)
    ax.set_xticks([pos + width*1.5 for pos in x])
    ax.set_xticklabels(hours, rotation=45, ha="right")
    ax.set_ylabel("Count")
    ax.set_title("Log Levels per Hour")
    ax.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    filename = input("Enter file name: ")
    log_lines = read_log(filename)
    print(f"Total lines: {len(log_lines)}")

    counts = count_log_levels(log_lines)
    print("Log level counts:", counts)

    ip_counts = extract_ip_counts(log_lines)
    print("\nIP address counts:")
    for ip, count in ip_counts.items():
        print(f"- {ip}: {count}")

    failed_logins = detect_failed_logins(log_lines)
    print("\nFailed login attempts:")
    if failed_logins:
        for ip, count in failed_logins.items():
            print(f"- {ip}: {count}")
    else:
        print("No failed login attempts detected.")

    hourly_levels = analyze_by_hour_and_level(log_lines)

    # User chooses output format
    print("\nChoose output format:")
    print("1. ASCII table")
    print("2. Graph")
    print("3. Both")
    choice = input("Enter 1, 2, or 3: ")

    if choice == "1":
        print_hourly_table(hourly_levels)
    elif choice == "2":
        plot_hourly_summary(hourly_levels)
    elif choice == "3":
        print_hourly_table(hourly_levels)
        plot_hourly_summary(hourly_levels)
    else:
        print("Invalid choice. Showing ASCII table by default.")
        print_hourly_table(hourly_levels)
