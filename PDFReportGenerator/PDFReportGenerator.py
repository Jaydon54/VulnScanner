from reportlab.lib.pagesizes import letter  #sets pdf size to satndars US letter
from reportlab.pdfgen import canvas #drawing board for report
from reportlab.lib import colors    #color for headers,tables,etc
from typing import List, Dict, Tuple   #type hints for clean code
from database import get_results_by_target  #pulls scan results form database
from CVE_Checker import CVEChecker  #pulls CVEChecker class

#------------------------------------------------
# Class Initialization
#------------------------------------------------
class PDFReportGen:
    def __init__(self):     
        self.CVE_Checker = CVEChecker() #opens CVEchecker 

    #------------------------------------------------
    def generate_report(self, target: str, filename: str = "scan_report.pdf") -> None:  #method for generating report
        results = get_results_by_target(target)

        if not results:
            print(f"No scan results foudn for {target}.")
            return 
        
        pdf = canvas.Canvas(filename, pagesize=letter) #creates bland pdf to draw on
        width, height = letter #paper dimensions
        y = height - 50  # Start 50 points from the top of the page
        #Report Title 
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(50, y, f"Vulnerability Scan Report for {target}")
        y -= 30  # Move down after title
        #Table Headers
        headers = ["Port", "Service", "Product", "Version", "State", "CVEs", "Risk Level"]
        pdf.setFont("Helvetica-Bold", 12)
        for i, header in enumerate(headers):
            pdf.drawString(50 + i * 80, y, header)
        y -= 20  # Move down after headers
        pdf.setFont("Helvetica", 10)  # Set normal font for content

        headers = ["Port", "Service", "Product", "Version", "State", "CVEs", "Risk Level"]
        pdf.setFont("Helvetica-Bold", 12)

        for row in results:
            _, target, port, service, state, extra_info, scan_type, timestamp = row
            product, version = self.extract_product_version(extra_info)

            # Get CVE info
            cve_info = self.cve_checker.check_scan_result(service, product, version)

            # Organize data nicely
            data = [
                str(port),
                service or "-",
                product or "-",
                version or "-",
                state or "-",
                ", ".join(cve_info["cves"]) or "None",
                cve_info["risk_level"]
            ]

            # Draw data into the PDF
            for i, item in enumerate(data):
                pdf.drawString(50 + i * 80, y, item)

            y -= 20  # Move down after each row

            # Start a new page if necessary
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

    #-----------------------------------------------------------
    def extract_product_version(self, extra_info: str) -> Tuple[str, str]:  #method for extrating product version
        if not extra_info:  #if extra info is empty then return two empty strings
            return "", ""

        parts = extra_info.split()  #splits a string into a list of words based on spaces
        if len(parts) >= 2:         #handles product and version based on spacing 
            product = " ".join(parts[:-1])  # all parts except the last one
            version = parts[-1]             # last part assumed to be the version
            return product, version
        else:   #handles weird cases
            return extra_info, ""
