# main file that executes the program
# Imports
from scanner.scanner import quick_scan, regular_scan, deep_scan
from database.database import init_db

def main():
    """
    Main function to run the scanner.
    """

    # Initialize the database
    init_db()
# Target input statement
    scan_type = input("What type of scan would you like to perform? (quick/regular/deep): ").lower()

    # Scan Type Input Validation
    while scan_type not in ["quick", "regular", "deep"]:
        scan_type = input("Invalid scan type. Please choose 'quick', 'regular', or 'deep':").lower()
        if(scan_type in ["quick", "regular", "deep"]):
            break
        return
    
    # Target input
    target = input("Enter target IP address, subnet, or domain: ")
    
    # Target Input validation
    if not target:
        target = input("Please enter a valid target:")
        return

    # Run the  scan
    if(scan_type == "quick"):
        quick_scan(target)
    elif(scan_type == "regular"):
        regular_scan(target)
    elif(scan_type == "deep"):
        deep_scan(target)

if __name__ == "__main__":
    main()