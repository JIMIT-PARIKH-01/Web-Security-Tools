import requests
import csv

INPUT_FILE = "domains.txt"
OUTPUT_FILE = "output.csv"
TIMEOUT = 10


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options"
]

def check_domain(domain):
    
    urls = [f"https://{domain}", f"http://{domain}"]
    last_error = "Unknown Error"

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True
            )

            
            found_headers_lower = [h.lower() for h in response.headers.keys()]
            missing = [h for h in SECURITY_HEADERS if h.lower() not in found_headers_lower]

            
            return {
                "Domain": domain,
                "Site Reachable": "Yes",
                "Final URL": response.url,
                "Response Status Code": response.status_code,
                "Missing Security Headers": ", ".join(missing) if missing else "None",
                "Error": ""
            }

        except requests.exceptions.RequestException as e:
            last_error = str(e)

    
    return {
        "Domain": domain,
        "Site Reachable": "No",
        "Final URL": "",
        "Response Status Code": "",
        "Missing Security Headers": "N/A",
        "Error": last_error
    }


def main():
    
    try:
        with open(INPUT_FILE, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: {INPUT_FILE} not found. Please create it.")
        return

    results = []

    for domain in domains:
        print(f"Checking: {domain}...")
        result = check_domain(domain)
        results.append(result)

    
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "Domain",
            "Site Reachable",
            "Final URL",
            "Response Status Code",
            "Missing Security Headers",  
            "Error"
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nScan complete. Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
