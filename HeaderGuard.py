"""HeaderGuard — the original batch security-header scanner (kept for continuity).

It now runs on the dependency-free ``websectools`` package, so it no longer
needs the third-party ``requests`` library. Behaviour is the same: read
``domains.txt`` and write a CSV report.
"""
from websectools import headers

INPUT_FILE = "domains.txt"
OUTPUT_FILE = "output.csv"


def main():
    try:
        rows = headers.scan_file(INPUT_FILE, OUTPUT_FILE)
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found. Please create it.")
        return
    for r in rows:
        print(f"Checking: {r['Domain']} … {r['Reachable']} "
              f"(grade {r['Grade'] or '-'})")
    print(f"\nScan complete. Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
