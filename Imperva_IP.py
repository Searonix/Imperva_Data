import os
import requests
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def setup_logging():
    """
    Setup logging configuration
    
    Returns:
        logging.Logger: Configured logger
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create log filename with timestamp - using Windows-safe format
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    log_filename = f"logs/{timestamp}_imperva_api.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("ImpervaAPI")
    logger.info(f"Log initialized at {timestamp}")
    return logger

def get_imperva_incidents(caid, since_timestamp=None, logger=None):
    """
    Fetch incidents from Imperva Analytics API with Delta Query support
    
    Args:
        caid (str): Customer Account ID
        since_timestamp (int, optional): Only fetch incidents after this timestamp
        logger (logging.Logger, optional): Logger object
        
    Returns:
        dict: API response data
    """
    # Get API credentials from environment variables
    api_id = os.getenv("IMPERVA_API_ID")
    api_key = os.getenv("IMPERVA_API_KEY")
    
    if not api_id or not api_key:
        error_msg = "IMPERVA_API_ID and IMPERVA_API_KEY must be set in .env file"
        if logger:
            logger.error(error_msg)
        raise ValueError(error_msg)
    
    # API endpoint
    url = "https://api.imperva.com/analytics/v1/incidents"
    
    # Request parameters
    params = {
        "caid": caid
    }
    
    # Add since_timestamp for Delta Query if provided
    if since_timestamp:
        params["from"] = since_timestamp
    
    # Request headers
    headers = {
        "x-API-Id": api_id,
        "x-API-Key": api_key,
        "Accept": "application/json"
    }
    
    # Make the API request
    if logger:
        logger.info(f"Making API request to {url} with params: {params}")
    
    response = requests.get(url, params=params, headers=headers)
    
    # Check if request was successful
    if response.status_code == 200:
        if logger:
            logger.info(f"API request successful")
        return response.json()
    else:
        error_msg = f"Error: {response.status_code} - {response.text}"
        if logger:
            logger.error(error_msg)
        return None

def extract_data_from_incidents(incidents, logger=None):
    """
    Extract IP addresses with reputation and domains from incidents
    
    Args:
        incidents (list): List of incident dictionaries
        logger (logging.Logger, optional): Logger object
        
    Returns:
        tuple: (dict of IP addresses with reputation, set of unique domains)
    """
    ip_data = {}  # Dictionary to store IP addresses and their reputation
    domains = set()
    
    # Handle both single incident (dict) and multiple incidents (list)
    if isinstance(incidents, dict):
        incidents = [incidents]
    
    if logger:
        logger.info(f"Extracting data from {len(incidents)} incidents")
    
    for incident in incidents:
        # Extract IP and reputation from dominant_attack_ip if it exists
        if 'dominant_attack_ip' in incident and 'ip' in incident['dominant_attack_ip']:
            ip = incident['dominant_attack_ip']['ip']
            if ip and ip.strip():  # Only add non-empty IPs
                reputation = incident['dominant_attack_ip'].get('reputation', [])
                ip_data[ip] = reputation
        
        # Extract domain from dominant_attacked_host if it exists
        if 'dominant_attacked_host' in incident and 'value' in incident['dominant_attacked_host']:
            domain = incident['dominant_attacked_host']['value']
            if domain and domain.strip():  # Only add non-empty domains
                domains.add(domain)
    
    if logger:
        logger.info(f"Extracted {len(ip_data)} unique IP addresses and {len(domains)} unique domains")
    
    return ip_data, domains

def save_domains_to_file(domains, logger=None, filename=None):
    """
    Save domains to a text file with timestamp
    
    Args:
        domains (set): Set of domains to save
        logger (logging.Logger, optional): Logger object
        filename (str, optional): Custom filename, if not provided a timestamped name will be used
    """
    # Create data directory if it doesn't exist
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # Generate timestamped filename if not provided - Windows-safe format
    if not filename:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        filename = f"{data_dir}/{timestamp}_domain_data.txt"
    else:
        # If filename is provided but doesn't include the directory, add it
        if not filename.startswith(data_dir):
            filename = f"{data_dir}/{filename}"
    
    if logger:
        logger.info(f"Saving domain data to {filename}")
    
    # Check if file exists
    file_exists = os.path.isfile(filename)
    
    # If file exists, read existing domains
    existing_domains = set()
    if file_exists:
        with open(filename, 'r') as f:
            existing_domains = set(line.strip() for line in f.readlines() if line.strip())
        if logger:
            logger.info(f"File exists, read {len(existing_domains)} existing domains")
    
    # Combine existing and new domains, filtering out empty strings
    domains = {domain for domain in domains if domain.strip()}
    all_domains = existing_domains.union(domains)
    
    # Write all domains to file
    with open(filename, 'w') as f:
        for domain in sorted(all_domains):
            if domain.strip():  # Only write non-empty domains
                f.write(f"{domain}\n")
    
    # Log stats
    new_domains = domains - existing_domains
    if logger:
        logger.info(f"Added {len(new_domains)} new domain entries")
        logger.info(f"Total unique domain entries: {len(all_domains)}")
    else:
        print(f"Added {len(new_domains)} new domain entries")
        print(f"Total unique domain entries: {len(all_domains)}")
    
    return all_domains

def save_ip_data_to_file(ip_data, logger=None, filename=None, detailed_filename=None):
    """
    Save IP addresses to a simple text file and detailed JSON file with reputations
    
    Args:
        ip_data (dict): Dictionary of IP addresses and their reputation
        logger (logging.Logger, optional): Logger object
        filename (str, optional): Custom filename for simple IP list
        detailed_filename (str, optional): Custom filename for detailed IP data
    """
    # Create data directory if it doesn't exist
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # Generate timestamped filenames if not provided - Windows-safe format
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    
    if not filename:
        filename = f"{data_dir}/{timestamp}_ip_data.txt"
    else:
        # If filename is provided but doesn't include the directory, add it
        if not filename.startswith(data_dir):
            filename = f"{data_dir}/{filename}"
    
    if not detailed_filename:
        detailed_filename = f"{data_dir}/{timestamp}_ip_detailed.json"
    else:
        # If filename is provided but doesn't include the directory, add it
        if not detailed_filename.startswith(data_dir):
            detailed_filename = f"{data_dir}/{detailed_filename}"
    
    if logger:
        logger.info(f"Saving IP data to {filename} and detailed data to {detailed_filename}")
    
    # Check if simple IP file exists
    file_exists = os.path.isfile(filename)
    
    # If file exists, read existing IPs
    existing_ips = set()
    if file_exists:
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f.readlines() if line.strip())
        if logger:
            logger.info(f"File exists, read {len(existing_ips)} existing IP addresses")
    
    # Get new IPs from ip_data dictionary
    new_ips = set(ip_data.keys())
    
    # Combine existing and new IPs, filtering out empty strings
    new_ips = {ip for ip in new_ips if ip.strip()}
    all_ips = existing_ips.union(new_ips)
    
    # Write all IPs to simple text file
    with open(filename, 'w') as f:
        for ip in sorted(all_ips):
            if ip.strip():  # Only write non-empty IPs
                f.write(f"{ip}\n")
    
    # Check if detailed IP file exists
    detailed_exists = os.path.isfile(detailed_filename)
    
    # If detailed file exists, read existing data
    existing_detailed = {}
    if detailed_exists:
        with open(detailed_filename, 'r') as f:
            try:
                existing_detailed = json.load(f)
            except json.JSONDecodeError:
                if logger:
                    logger.warning(f"Could not parse existing JSON file {detailed_filename}, creating new file")
    
    # Update existing data with new data
    for ip, reputation in ip_data.items():
        if ip in existing_detailed:
            # Combine reputations without duplicates
            existing_rep = set(existing_detailed[ip])
            new_rep = set(reputation)
            combined_rep = list(existing_rep.union(new_rep))
            existing_detailed[ip] = combined_rep
        else:
            existing_detailed[ip] = reputation
    
    # Write all detailed data to JSON file
    with open(detailed_filename, 'w') as f:
        json.dump(existing_detailed, f, indent=2)
    
    # Log stats
    added_ips = new_ips - existing_ips
    if logger:
        logger.info(f"Added {len(added_ips)} new IP entries")
        logger.info(f"Total unique IP entries: {len(all_ips)}")
    else:
        print(f"Added {len(added_ips)} new IP entries")
        print(f"Total unique IP entries: {len(all_ips)}")
    
    return all_ips

def save_last_query_timestamp(timestamp, logger=None, filename=None):
    """
    Save the timestamp of the last query
    
    Args:
        timestamp (int): Timestamp in milliseconds
        logger (logging.Logger, optional): Logger object
        filename (str, optional): Name of the file to save to
    """
    # Create data directory if it doesn't exist
    data_dir = "data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # Generate filename if not provided - Windows-safe format
    if not filename:
        timestamp_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        filename = f"{data_dir}/{timestamp_str}_last_query_timestamp.txt"
    else:
        # If filename is provided but doesn't include the directory, add it
        if not filename.startswith(data_dir):
            filename = f"{data_dir}/{filename}"
    
    with open(filename, 'w') as f:
        f.write(str(timestamp))
    
    if logger:
        logger.info(f"Saved last query timestamp {timestamp} to {filename}")

def get_last_query_timestamp(logger=None, filename=None):
    """
    Get the timestamp of the last query
    
    Args:
        logger (logging.Logger, optional): Logger object
        filename (str, optional): Name of the file to read from
        
    Returns:
        int or None: Timestamp in milliseconds or None if file doesn't exist
    """
    # Use default filename if not provided
    if not filename:
        filename = "data/last_query_timestamp.txt"
    
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            timestamp = int(f.read().strip())
            if logger:
                logger.info(f"Retrieved last query timestamp: {timestamp}")
            return timestamp
    
    if logger:
        logger.info("No previous timestamp found")
    return None

def fetch_all_incidents_with_pagination(caid, logger=None, since_timestamp=None, page_size=100):
    """
    Fetch all incidents with pagination support
    
    Args:
        caid (str): Customer Account ID
        logger (logging.Logger, optional): Logger object
        since_timestamp (int, optional): Only fetch incidents after this timestamp
        page_size (int): Number of incidents to fetch per page
        
    Returns:
        list: List of all incidents
    """
    all_incidents = []
    page = 1
    more_incidents = True
    
    if logger:
        logger.info(f"Starting to fetch incidents with pagination, page size: {page_size}")
    
    while more_incidents:
        # Get API credentials from environment variables
        api_id = os.getenv("IMPERVA_API_ID")
        api_key = os.getenv("IMPERVA_API_KEY")
        
        # API endpoint
        url = "https://api.imperva.com/analytics/v1/incidents"
        
        # Request parameters
        params = {
            "caid": caid,
            "page": page,
            "page_size": page_size
        }
        
        # Add since_timestamp for Delta Query if provided
        if since_timestamp:
            params["from"] = since_timestamp
        
        # Request headers
        headers = {
            "x-API-Id": api_id,
            "x-API-Key": api_key,
            "Accept": "application/json"
        }
        
        if logger:
            logger.info(f"Fetching page {page}...")
        else:
            print(f"Fetching page {page}...")
        
        # Make the API request
        response = requests.get(url, params=params, headers=headers)
        
        # Check if request was successful
        if response.status_code == 200:
            incidents = response.json()
            
            # Handle both array and single object responses
            if isinstance(incidents, dict):
                incidents = [incidents]
            elif not incidents:  # Empty array
                incidents = []
            
            all_incidents.extend(incidents)
            
            if logger:
                logger.info(f"Fetched {len(incidents)} incidents from page {page}")
            
            # If we got less than page_size incidents, we've reached the end
            if len(incidents) < page_size:
                more_incidents = False
                if logger:
                    logger.info("Reached last page of results")
            else:
                page += 1
        else:
            error_msg = f"Error fetching page {page}: {response.status_code} - {response.text}"
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
            more_incidents = False
    
    if logger:
        logger.info(f"Total incidents fetched: {len(all_incidents)}")
    else:
        print(f"Total incidents fetched: {len(all_incidents)}")
    
    return all_incidents

def create_summary_report(ip_count, domain_count, incident_count, timestamp, logger=None):
    """
    Create a summary report file
    
    Args:
        ip_count (int): Number of unique IP addresses
        domain_count (int): Number of unique domains
        incident_count (int): Number of incidents processed
        timestamp (str): Timestamp string
        logger (logging.Logger, optional): Logger object
    """
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    # Create report filename with timestamp
    report_filename = f"{reports_dir}/{timestamp}_summary.txt"
    
    # Get current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create report content
    report_content = f"""Imperva Incident Data Extraction Summary
Report Generated: {current_time}

Data Collection Information:
---------------------------
Total Incidents Processed: {incident_count}
Unique IP Addresses Found: {ip_count}
Unique Domains Found: {domain_count}

File Information:
---------------
IP Address List: data/{timestamp}_ip_data.txt
IP Address Details: data/{timestamp}_ip_detailed.json
Domain List: data/{timestamp}_domain_data.txt
Timestamp File: data/{timestamp}_last_query_timestamp.txt

This report was automatically generated by the Imperva Data Extractor tool.
"""
    
    # Write report to file
    with open(report_filename, 'w') as f:
        f.write(report_content)
    
    if logger:
        logger.info(f"Created summary report at {report_filename}")
    else:
        print(f"Created summary report at {report_filename}")

if __name__ == "__main__":
    # Setup logging
    logger = setup_logging()
    
    # Customer Account ID
    caid = os.getenv("CLID")
    
    try:
        logger.info("Starting Imperva incidents extraction process")
        
        # Get the timestamp of the last query for Delta Query
        last_timestamp = get_last_query_timestamp(logger)
        if last_timestamp:
            logger.info(f"Using Delta Query from timestamp: {last_timestamp}")
            logger.info(f"({datetime.fromtimestamp(last_timestamp/1000).strftime('%Y-%m-%d %H:%M:%S')})")
        
        # Get all incidents with pagination
        incidents = fetch_all_incidents_with_pagination(caid, logger, last_timestamp)
        
        if incidents:
            # Get current timestamp for the next Delta Query
            current_timestamp = int(datetime.now().timestamp() * 1000)
            
            # Extract IP data and domains
            ip_data, domains = extract_data_from_incidents(incidents, logger)
            
            # Generate timestamped filenames - Windows-safe format
            timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
            ip_filename = f"{timestamp}_ip_data.txt"
            ip_detailed_filename = f"{timestamp}_ip_detailed.json"
            domain_filename = f"{timestamp}_domain_data.txt"
            timestamp_filename = f"{timestamp}_last_query_timestamp.txt"
            
            # Save IP data to files
            all_ips = save_ip_data_to_file(ip_data, logger, ip_filename, ip_detailed_filename)
            
            # Save domains to a text file
            all_domains = save_domains_to_file(domains, logger, domain_filename)
            
            # Save the current timestamp for the next Delta Query
            save_last_query_timestamp(current_timestamp, logger, timestamp_filename)
            
            # Create summary report
            create_summary_report(len(all_ips), len(all_domains), len(incidents), timestamp, logger)
            
            logger.info(f"Successfully extracted data from Imperva API")
            logger.info(f"Number of incidents processed: {len(incidents)}")
            logger.info(f"Number of unique IP addresses found: {len(ip_data)}")
            logger.info(f"Number of unique domains found: {len(domains)}")
        else:
            logger.warning("No incidents found or error occurred")
    
    except Exception as e:
        logger.exception(f"Error in main process: {str(e)}")