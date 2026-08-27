from log_parser import parse_file
from collections import Counter 


records = parse_file("access.log")

total_requests = len(records)

print(f"Total requests: {total_requests}")


errors = [record for record in records if record.status >= 400]

error_count = len(errors)

print(f"Errors: {error_count}")


error_rate = (error_count / total_requests) * 100

print(f"Error rate: {error_rate:.2f}%")


ip_counts = Counter(record.ip for record in records)

print("\nTop IP Addresses:")

for ip, count in ip_counts.most_common():
    print(f"{ip}: {count} requests")

    total_latency = sum(record.latency for record in records)

average_latency = total_latency / total_requests

print(f"\nAverage latency: {average_latency:.2f} ms")

path_counts = Counter(record.path for record in records)

print("\nMost Requested Endpoints:")

for path, count in path_counts.most_common():
    print(f"{path}: {count} requests")
