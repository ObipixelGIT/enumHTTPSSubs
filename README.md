# enumHTTPSSubs
Enumerate subdomains via Certificate Transparency (CT) logs of a target domain and checking if they are live!

## How this script works?

This is a Python script for enumerating subdomains via Certificate Transparency (CT) logs. The script uses the crt.sh website to query the CT logs for certificates that contain the target domain. It then extracts the subdomains from the certificates and returns them.

The script also has an option to check if the subdomains are live by making an HTTP request to the domain and checking if the response code is 200.

The script uses the requests library to make HTTP requests and the json library to parse JSON responses. It also uses the argparse library to parse command-line arguments.

The SubdomainEnumerator class has three methods:

- init: Initializes the class and sets the target domain and whether to check for live subdomains.
- get_subdomains: Queries the CT logs for certificates that contain the target domain and extracts the subdomains from the certificates.
- check_live_domains: Checks if the subdomains are live by making an HTTP request and checking the response code.
- enumerate_subdomains: Calls get_subdomains and optionally calls check_live_domains to print the subdomains.

The main function uses argparse to parse the command-line arguments and creates an instance of the SubdomainEnumerator class to enumerate the subdomains.

Overall, this script is a useful tool for enumerating subdomains of a target domain and checking if they are live. However, it is important to note that CT logs may not contain all subdomains and there may be false positives. It is also important to use this tool responsibly and only on domains that you have permission to test.

## Requirements

Install your libraries:
```bash
pip3 install requests, json, argparse, signal
```

## Permissions

Ensure you give the script permissions to execute. Do the following from the terminal:
```bash
sudo chmod +x enumHTTPSSubs.py
```

## Usage
```bash
sudo python3 enumHTTPSSubs.py [-h] -t TARGET_DOMAIN [-l]
```
```
options:
  -h, --help            show this help message and exit
  -t TARGET_DOMAIN, --target TARGET_DOMAIN
                        Domain to enumerate
  -l, --live            Also check if domains are live (HTTP 200)
  ```
 
 ## Example script
 ```python
 #!/usr/bin/env python3

import sys  # for system-specific parameters and functions
import requests  # for making HTTP requests
import json  # for parsing JSON responses
import argparse  # for parsing command-line arguments
import signal  # for handling interrupts
import os  # for system-specific operating system functionality

class SubdomainEnumerator:
    
    def __init__(self, target_domain, check_live):
        """
        Initialize the class with the target domain and whether to check for live subdomains.
        """
        self.target_domain = target_domain
        self.check_live = check_live
        signal.signal(signal.SIGINT, self.ctrl_c)  # handle interrupt signal

    def ctrl_c(self, sig, frame):
        """
        Handle the interrupt signal (CTRL+C).
        """
        print("\n{} chose to quit via CTRL+C!".format(os.environ['USER']))
        sys.exit(0)

    def get_subdomains(self):
        """
        Query the Certificate Transparency logs for certificates that contain the target domain and extract the subdomains from the certificates.
        """
        url = "https://crt.sh/?q=%25.{}&output=json".format(self.target_domain)
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        req = requests.get(url, headers={'User-Agent': user_agent})

        if req.ok:
            data = req.content.decode('utf-8')
            real_json = json.loads("[{}]".format(data.replace('}{', '},{')))
            domains = []
            for certs in real_json:
                for cert in certs:
                    domains.append(cert['name_value'])
            unique_domains = sorted(set(domains))
            return unique_domains

    def check_live_domains(self, domains):
        """
        Check if the subdomains are live by making an HTTP request and checking the response code.
        """
        count = 0
        for domain in domains:
            try:
                if "*" in domain:
                    continue
                if requests.get("https://{}".format(domain)).status_code == 200:
                    print("{}".format(domain))
                    count += 1
            except Exception:
                continue
        if count == 0:
            print("None")

    def enumerate_subdomains(self):
        """
        Call get_subdomains to query the CT logs for certificates, and optionally call check_live_domains to check if the subdomains are live.
        """
        domains = self.get_subdomains()
        if self.check_live:
            self.check_live_domains(domains)
        else:
            for domain in domains:
                print("{}".format(domain))

def main():
    """
    Parse command-line arguments and create an instance of the SubdomainEnumerator class to enumerate the subdomains.
    """
    parser = argparse.ArgumentParser(description="Enumerate HTTPS enabled subdomains via Certificate Transparency")
    parser.add_argument("-t", "--target", action='store', dest='target_domain', required=True,  
                        help="Domain to enumerate")
    parser.add_argument("-l", "--live", action='store_true',  
                        help="Also check if domains are live (HTTP 200)")
    args = parser.parse_args()

    enumerator = SubdomainEnumerator(args.target_domain, args.live)
    enumerator.enumerate_subdomains()

if __name__== "__main__":
    main()
 ```

## Example output
```bash
sudo python3 enumHTTPSSubs.py -t obisec.com  
```
```
academy.obisec.com
cbcp-course.obisec.com
obisec.com
www.obisec.com
```

## License Information

This library is released under the [Creative Commons ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/). You are welcome to use this library for commercial purposes. For attribution, we ask that when you begin to use our code, you email us with a link to the product being created and/or sold. We want bragging rights that we helped (in a very small part) to create your 9th world wonder. We would like the opportunity to feature your work on our homepage.
