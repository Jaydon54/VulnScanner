# main file

# Imports
from scanner.scanner import quick_scan  # type: ignore

def main():
    """
    Main function to run the scanner.
    """
   # Target input statement
    target = input("Enter target IP address, subnet, or domain: ")
    # ADD INPUT VALIDATION HERE
    
    # Run the quick scan
    quick_scan(target)

if __name__ == "__main__":
    main()