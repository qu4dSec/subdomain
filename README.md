
## This tool has several tasks:

1. It performs subdomain scans using the **[securitytrails](https://securitytrails.com/) API**.
2. It checks if the given domain is **[blacklisted](https://www.blacklistalert.org/)**.
3. It checks the **SSL certificate** status for each subdomain found. If an SSL certificate does not exist, it warns the user. Additionally, if the SSL certificate has less than 4 months left, it gives a warning as **"Less than 4 months left (time)"**.
4. Finally, it writes the subdomains it finds to a text file.

## Usage of this tool:

``` 
python3 subdomain-ssl-blacklist-checker.py example.com "-k" or "--api-key"("securitytrails API required (without quotes)") "-o" or "--output-file" example.txt
```

The **domain**, **api-key**, and **output-file** parameters must be filled in.




