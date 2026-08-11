from collections import Counter


def analyze_log(filename):
    levels = Counter()
    ips = Counter()
    errors = Counter()

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            # Count log levels
            if "INFO" in line:
                levels["INFO"] += 1

            elif "WARNING" in line:
                levels["WARNING"] += 1

            elif "ERROR" in line:
                levels["ERROR"] += 1
                errors[line] += 1

            # Find IP address
            if "IP=" in line:
                ip = line.split("IP=")[1]
                ips[ip] += 1

    print("\n===== LOG ANALYZER REPORT =====")

    print("\nLog Levels:")
    for level, count in levels.items():
        print(f"{level}: {count}")

    print("\nMost Common IP Addresses:")
    for ip, count in ips.most_common():
        print(f"{ip}: {count}")

    print("\nErrors:")
    for error, count in errors.most_common(5):
        print(f"{count}x - {error}")


analyze_log("sample.log")