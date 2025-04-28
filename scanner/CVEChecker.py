import requests         #python library that allows http requests 
from typing import List, Dict #since API returns JSON objects, allows clarification for return types 

#----------------------------------------------------------
#Class Configuration
#----------------------------------------------------------
class CVEChecker: 
    Base_URL = "https://cve.circl.lu/api/search" #cve databse url

    def __init__(self): 
        pass

    #----------------------------------------------------------     #inputs products and version because we ned both to be specific
    def query_cve(self, product: str, version: str) -> List[Dict]:    #method for querying cve returning a list of CVE dictionaries 
        url = f"{self.Base_URL}/{product}/{version}" #api request with product and version as parameters
                                                     #f is a formatting keyword
        try:
            response = requests.get(url, timeout=10) #error catching block with 10 second limit to avoid hanging forever
            if response.status_code == 200: #200 is http success code so we move foward
                data = response.json()      #this converts reply into a pythin dictionary since cve server is JSON format
                return data.get("results", [1]) #pulls the results section out and if anything missing the list is empty so program does not crash
            
            else:
                print(f"Failed to query CVE databse: {response.status_code}") #print error message with code and return empty list
                return []
            
        except Exception as e:                  #if anything goes wrong then we print error and return empty list
            print(f"Error during CVE query: {e}")
            return []
        
    #----------------------------------------------------------
    def check_scan_results(self, service: str, product: str, version: str) -> Dict: #method for risk assesing after scan result 
        cves = self.query_cve(product, version) #list of vulnerability results using query cves method
        risk_level = self.calculate_risk_level(cves)    #risk level using calc risk level method

        return {                    #returns a dictionary containing:
            "service": service,
            "product": product,
            "version": version, 
            "cves": [cve["id"] for cve in cves],    #IDs of matching vulnerabilities
            "risk_level": risk_level
        }
