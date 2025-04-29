
# reports/pdf_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from typing import List, Tuple
from database.database import get_results_by_target
from CVE_Checker.CVE_Checker import CVEChecker

class PDFReportGen:
    def __init__(self, api_key):
        self.CVE_Checker = CVEChecker(api_key)

    def generate_report(self, target: str, filename: str = "scan_report.pdf") -> None:
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        c.setFont("Helvetica-Bold", 16)
        c.drawString(200, 750, "Network Vulnerability Report")

        c.setFont("Helvetica", 12)
        c.drawString(50, 720, f"Target: {target}")
        
        y_position = 680

        headers = ["Port", "Service", "Product", "Version", "State", "CVEs", "Risk Level"]
        column_positions = [50, 100, 170, 270, 370, 430, 530]

        # Draw table headers
        c.setFont("Helvetica-Bold", 10)
        for header, x in zip(headers, column_positions):
            c.drawString(x, y_position, header)
        y_position -= 20

        c.setFont("Helvetica", 9)

        results = self.extract_report_data(target)

        for result in results:
            if y_position < 100:  # If near bottom, create new page
                c.showPage()
                c.setFont("Helvetica-Bold", 10)
                for header, x in zip(headers, column_positions):
                    c.drawString(x, 750, header)
                y_position = 730
                c.setFont("Helvetica", 9)

            port, service, product, version, state, cves, risk_level = result

            cves_display = cves if len(cves) <= 40 else cves[:37] + "..."

            row_data = [str(port), service, product, version, state, cves_display, risk_level]

            for data, x in zip(row_data, column_positions):
                c.drawString(x, y_position, data)

            y_position -= 20

        c.save()
        print(f"PDF report generated: {filename}")

    def extract_report_data(self, target: str) -> List[Tuple]:     #Fetch results from database and structure them for PDF report.
        raw_results = get_results_by_target(target)
        report_data = []

        for row in raw_results:
            id, target, port, service, state, extra_info, scan_type, timestamp, risk_level = row

            # Parse extra_info into product and version
            product, version = self.extract_product_version(extra_info)

            # Placeholder for CVEs if needed (for now just show 'None')
            cves = "None"

            # Return exactly 7 fields
            report_data.append((port, service, product, version, state, cves, risk_level))

        return report_data

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
