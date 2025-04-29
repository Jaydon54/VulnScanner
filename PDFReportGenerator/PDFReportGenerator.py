# reports/pdf_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from typing import List, Tuple
from database.database import get_results_by_target
from CVE_Checker.CVE_Checker import CVEChecker

api_key = "835093cb-2fed-4d1b-af78-ad31e17e29e0" 

class PDFReportGen:
    def __init__(self, api_key):
        self.CVE_Checker = CVEChecker(api_key)

    def generate_report(self, target: str, filename: str = "scan_report.pdf") -> None:
        results = get_results_by_target(target)

        if not results:
            print(f"No scan results found for {target}.")
            return
        
        pdf = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        y = height - 50

        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(50, y, f"Vulnerability Scan Report for {target}")
        y -= 30

        headers = ["Port", "Service", "Product", "Version", "State", "CVEs", "Risk Level"]
        pdf.setFont("Helvetica-Bold", 12)
        for i, header in enumerate(headers):
            pdf.drawString(50 + i * 80, y, header)
        y -= 20
        pdf.setFont("Helvetica", 10)

        for row in results:
            _, target, port, service, state, extra_info, scan_type, timestamp, risk_level = row
            product, version = self.extract_product_version(extra_info)

            cve_info = self.CVE_Checker.check_scan_results(service, product, version)

            data = [
                str(port),
                service or "-",
                product or "-",
                version or "-",
                state or "-",
                ", ".join(cve_info["cves"]) or "None",
                risk_level
            ]

            for i, item in enumerate(data):
                pdf.drawString(50 + i * 80, y, item)

            y -= 20

            if y < 100:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica-Bold", 12)
                for i, header in enumerate(headers):
                    pdf.drawString(50 + i * 80, y, header)
                y -= 20
                pdf.setFont("Helvetica", 10)

        pdf.save()
        print(f"PDF report generated: {filename}")

    def extract_product_version(self, extra_info: str) -> Tuple[str, str]:
        if not extra_info:
            return "", ""

        parts = extra_info.split()
        if len(parts) >= 2:
            product = " ".join(parts[:-1])
            version = parts[-1]
            return product, version
        else:
            return extra_info, ""
