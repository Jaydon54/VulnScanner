# CVE_Checker/CVE_Checker.py (Updated for NIST NVD API)
import requests
from typing import List, Dict

class CVEChecker:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def query_cve(self, product: str, version: str) -> List[Dict]:
        keyword = f"{product} {version}"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20  
        }
        headers = {
            "apiKey": self.api_key
        }

        try:
            response = requests.get(self.BASE_URL, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            else:
                print(f"Failed to query NVD: Status {response.status_code}")
                return []
        except Exception as e:
            print(f"Error during CVE query: {e}")
            return []

    def check_scan_results(self, service: str, product: str, version: str) -> Dict:
        cve_entries = self.query_cve(product, version)
        risk_level = self.calculate_risk_level(cve_entries)

        return {
            "service": service,
            "product": product,
            "version": version,
            "cves": [entry["cve"]["id"] for entry in cve_entries if "cve" in entry],
            "risk_level": risk_level
        }

    def calculate_risk_level(self, cve_entries: List[Dict]) -> str:
        if not cve_entries:
            return "Low"

        max_cvss = 0
        for entry in cve_entries:
            metrics = entry["cve"].get("metrics", {})

            # Prefer CVSS v3.1 if available
            if "cvssMetricV31" in metrics:
                for metric in metrics["cvssMetricV31"]:
                    score = metric["cvssData"].get("baseScore", 0)
                    if score > max_cvss:
                        max_cvss = score
            # Otherwise fall back to CVSS v2
            elif "cvssMetricV2" in metrics:
                for metric in metrics["cvssMetricV2"]:
                    score = metric["cvssData"].get("baseScore", 0)
                    if score > max_cvss:
                        max_cvss = score

        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        else:
            return "Low"
