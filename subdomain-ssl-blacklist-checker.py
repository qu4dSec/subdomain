import argparse
import requests
import datetime
import ssl
import socket


def scan_subdomains(api_key, domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    response = requests.get(url, headers=headers)

    # If the request is successful, return the list of subdomains and check SSL certificate
    if response.status_code == 200:
        subdomains = response.json()["subdomains"]
        for subdomain in subdomains:
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=subdomain + '.' + domain) as s:
                    s.settimeout(2)
                    s.connect((subdomain + '.' + domain, 443))
                    cert = s.getpeercert()
                    expires = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expires - datetime.datetime.now()).days
                    if days_left < 120:
                        print(f"\033[31m[-]\033[0m Warning: SSL certificate for \033[32m{subdomain}.{domain}\033[0m expires in less than 4 months ({days_left} days)")
                    else:
                        print(f"\033[32m[+]\033[0m SSL certificate for \033[32m{subdomain}.{domain}\033[0m is valid")
            except:
                print(f"\033[31m[-]\033[0m Warning: No SSL certificate for \033[31m{subdomain}.{domain}\033[0m")

        # Check if domain is blacklisted using blacklistalert.org
        url = f"https://www.blacklistalert.org/?q={domain}"
        response = requests.get(url)
        if "blacklisted" in response.text:
            blacklist_name = "unknown"
            try:
                blacklist_name = response.text.split("<h3 class=\"result_title\">")[1].split("</h3>")[0]
            except IndexError:
                pass
            
            if blacklist_name == "unknown":
                print(f"\033[31m[-]\033[0m Warning: \033[34m{domain}\033[0m is blacklisted by an unknown blacklist")
            else:
                print(f"\033[31m[-]\033[0m Warning: \033[34m{domain}\033[0m is blacklisted by \033[31m{blacklist_name}\033[0m")

        return subdomains
    else:
        # If the request fails, print an error message and return an empty list
        print(f"\033[31m[-]\033[0m Error: {response.status_code}")
        return []



# Define a main function to parse command line arguments and scan subdomains
def main():
    # Define command line arguments
    parser = argparse.ArgumentParser(description="Scan subdomains using the SecurityTrails API")
    parser.add_argument("domain", help="the domain to scan")
    parser.add_argument("-k", "--api-key", help="your SecurityTrails API key", required=True)
    parser.add_argument("-o", "--output-file", help="file to write subdomains to")
    args = parser.parse_args()
    
    # Scan subdomains for the given domain using the SecurityTrails API
    subdomains = scan_subdomains(args.api_key, args.domain)
    
    # Print the results to the console
    print("\033[32m[+]\033[0m Found \033[33m{}\033[0m subdomains for \033[34m{}\033[0m".format(len(subdomains), args.domain))
    for subdomain in subdomains:
        print("\033[32m[+]\033[0m \033[36m{}\033[0m".format(subdomain + '.' + args.domain))
    
    # If an output file is specified, write the results to the file
    if args.output_file:
        with open(args.output_file, "w") as f:
            for subdomain in subdomains:
                f.write(subdomain + '.' + args.domain + "\n")


# Call the main function when the script is executed
if __name__ == "__main__":
    main()