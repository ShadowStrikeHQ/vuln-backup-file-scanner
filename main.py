import argparse
import requests
import logging
import os
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of common backup file extensions to scan for
BACKUP_EXTENSIONS = ['.bak', '.old', '.swp', '.tmp', '~', '.backup', '.orig', '.inc']

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans a website for common backup file extensions to identify potential information leakage.")
    parser.add_argument("url", help="The URL of the website to scan.")
    parser.add_argument("-o", "--output", help="The output file to save the results to (optional).", default=None)  # Allow specifying an output file
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the provided URL is a valid URL.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme (e.g., http, https) and network location (e.g., example.com)
    except:
        return False

def check_backup_file(url, base_url, session):
    """
    Checks if a backup file exists at the given URL.

    Args:
        url (str): The URL of the backup file to check.
        base_url (str): The base URL of the website.
        session (requests.Session): The requests session to use for making requests.

    Returns:
        bool: True if the backup file exists, False otherwise.
    """
    try:
        response = session.get(url, allow_redirects=True)  # Follow redirects
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        if response.status_code == 200:
            logging.info(f"Found backup file: {url}")
            return True
        else:
            logging.debug(f"URL {url} returned status code: {response.status_code}") # Reduced verbosity
            return False

    except requests.exceptions.RequestException as e:  # Catch all request exceptions (e.g., connection errors, timeout)
        logging.error(f"Error checking {url}: {e}")
        return False

def scan_for_backup_files(base_url):
    """
    Scans a website for common backup file extensions.

    Args:
        base_url (str): The base URL of the website to scan.

    Returns:
        list: A list of URLs where backup files were found.
    """
    found_files = []
    session = requests.Session()  # Use a session for connection pooling

    try:
        # Fetch the base URL to identify potential file names
        response = session.get(base_url, allow_redirects=True)
        response.raise_for_status()
        # Extract filename from URL
        url_path = urlparse(base_url).path
        if url_path.endswith('/'):
            filename = "index.html"  # default filename, or you could skip this URL since no filename exists
        else:
            filename = os.path.basename(url_path)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching base URL {base_url}: {e}")
        return found_files  # Return empty list if base URL can't be fetched

    # Ensure that base URL doesn't end with "/" (handled above)
    if base_url.endswith("/"):
        base_url = base_url[:-1] # Removing the trailing forward slash


    for ext in BACKUP_EXTENSIONS:
        # Check backup file with the same filename as the target URL
        backup_url = f"{base_url}{ext}"
        if check_backup_file(backup_url, base_url, session):
            found_files.append(backup_url)

        if filename != "index.html":  # only check for file-specific backups if the base url has a filename
            backup_url_filename = f"{base_url}/{filename}{ext}" # Create a backup file URL using the filename
            if check_backup_file(backup_url_filename, base_url, session):
                found_files.append(backup_url_filename)

    return found_files


def main():
    """
    Main function to execute the backup file scanner.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        return

    logging.info(f"Scanning for backup files at: {args.url}")
    found_files = scan_for_backup_files(args.url)

    if found_files:
        logging.info("Found the following backup files:")
        for file in found_files:
            logging.info(file)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    for file in found_files:
                        f.write(file + "\n")
                logging.info(f"Results saved to: {args.output}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
    else:
        logging.info("No backup files found.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic scan: python vuln_backup_file_scanner.py https://www.example.com
# 2. Scan with verbose output: python vuln_backup_file_scanner.py https://www.example.com -v
# 3. Scan and save results to a file: python vuln_backup_file_scanner.py https://www.example.com -o results.txt
# 4. If target url is a file: python vuln_backup_file_scanner.py https://www.example.com/file.html