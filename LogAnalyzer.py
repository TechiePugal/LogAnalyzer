import re
import csv
from collections import defaultdict

# Default threshold for suspicious activity
DEFAULT_FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Generator to parse each line in the log file.
    """
    try:
        with open(file_path, 'r') as file:
            for line in file:
                yield line.strip()
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        exit(1)

def analyze_logs(log_lines, failed_login_threshold=DEFAULT_FAILED_LOGIN_THRESHOLD):
    """
    Analyze log lines for:
    - Requests per IP
    - Most accessed endpoint
    - Suspicious activity
    """
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    
    for line in log_lines:
        # Regex to extract IP, endpoint, and status code
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*"([A-Z]+) ([^ ]+) HTTP/.*" (\d+)', line)
        if match:
            ip, method, endpoint, status = match.groups()
            ip_counts[ip] += 1
            endpoint_counts[endpoint] += 1
            
            # Detect failed login attempts
            if status == '401' or "Invalid credentials" in line:
                failed_logins[ip] += 1
    
    # Identify the most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=("", 0))
    
    # Filter suspicious IPs based on threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}
    
    return ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips

def save_to_csv(ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips):
    """
    Save the analysis results to a CSV file.
    """
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_results(ip_counts, most_accessed_endpoint, suspicious_ips):
    """
    Display the analysis results in the terminal.
    """
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count:<20}")

def main():
    # Configuration
    log_file = 'sample.log'
    failed_login_threshold = DEFAULT_FAILED_LOGIN_THRESHOLD

    # Parse and analyze the log file
    log_lines = parse_log_file(log_file)
    ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips = analyze_logs(
        log_lines, failed_login_threshold
    )
    
    # Display results in terminal
    display_results(ip_counts, most_accessed_endpoint, suspicious_ips)
    
    # Save results to CSV
    save_to_csv(ip_counts, endpoint_counts, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'")

if __name__ == "__main__":
    main()
