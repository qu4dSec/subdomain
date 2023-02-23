import requests

API_ENDPOINT = 'https://www.virustotal.com/api/v3/domains/{}/subdomains'
HEADERS = {'x-apikey': 'virustotal-api here'}

def get_subdomains(domain):
    url = API_ENDPOINT.format(domain)
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return [subdomain['id'] for subdomain in response.json()['data']]
    else:
        raise Exception('An error occurred while making the request')

if __name__ == '__main__':
    domain = 'domain address here'
    subdomains = get_subdomains(domain)
    print(f'Subdomains of {domain}:')
    for subdomain in subdomains:
        print(subdomain)