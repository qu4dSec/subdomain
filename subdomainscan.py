import requests
import json

# Replace YOUR_API_KEY with your actual VirusTotal API key
API_KEY = 'virustotal-api here'

# The domain to check for subdomains
domain = 'domain address here'

# Make a request to the VirusTotal API to get a list of subdomains
response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains', headers={'x-apikey': API_KEY})

# Check the status code of the response
if response.status_code == 200:
    # Load the JSON data from the response
    data = json.loads(response.text)

    # Print the list of subdomains
    print(f'Subdomains of {domain}:')
    for subdomain in data['data']:
        print(subdomain['id'])
else:
    # There was an error making the request
    print('An error occurred while making the request')