# CVE_Checker/CVE_Checker.py
import requests
from typing import List, Dict

class CVEChecker:
    Base_URL = "https://cve.circl.lu/api/search"

    def __init__(self):
        pass

    def query_cve(self, product: str, version: str) -> List[Dict]:
        url = f"{self.Base_URL}/{product}/{version}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get("results", [])
            elif response.status_code == 404:
                print(f"404 Not Found: No CVE data found for {product} {version}")
                return []
            else:
                print(f"Failed to query CVE database: {response.status_code}")
                return []
        except Exception as e:
            print(f"Error during CVE query: {e}")
            return []

    def check_scan_results(self, service: str, product: str, version: str) -> Dict:
        cves = self.query_cve(product, version)
        risk_level = self.calculate_risk_level(cves)

        return {
            "service": service,
            "product": product,
            "version": version,
            "cves": [cve.get("id", "unknown") for cve in cves],
            "risk_level": risk_level
        }

    def calculate_risk_level(self, cves: List[Dict]) -> str:
        if not cves:
            return "Low"

        max_cvss = 0
        for cve in cves:
            cvss_score = cve.get("cvss", 0)
            if cvss_score > max_cvss:
                max_cvss = cvss_score

        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        else:
            return "Low"
