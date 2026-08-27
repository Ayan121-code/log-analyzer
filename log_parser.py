from dataclasses import dataclass


@dataclass
class LogRecord:
    method: str
    path: str
    status: int
    latency: int
    ip: str



def parse_line(line: str) -> LogRecord:
    parts = line.strip().split()

    method = parts[0]
    path = parts[1]
    status = int(parts[2])
    latency = int(parts[3])
    ip = parts[4]

    return LogRecord(
        method=method,
        path=path,
        status=status,
        latency=latency,
        ip=ip
    )


def parse_file(filename: str) -> list[LogRecord]:
    records = []

    with open(filename, "r") as file:
        for line in file:
            if line.strip():
                records.append(parse_line(line))

    return records


