# F5 XC Security Event Logs Extraction

This Python script retrieves security events for all load balancers configured in a specific Namespace / Tenant using the F5 Distributed Cloud API. It also provides functionality to retrieve all security events for a specific load balancer. The retrieved data can be saved to a Excel or JSON file.

## Prerequisites

- Python 3.x
- `requests` library
- `pandas` library
- `argparse` library

## Getting Started

Install the required libraries using the following command:

```bash
pip install -r requirements.txt
```

Clone the repository or download the script.

You need to provide the following global variables in the script according to your environment (passed as command line arguments):

- TENANT: The tenant information for constructing the API URL.
- NAMESPACE: The namespace information for constructing the API URL.
- TOKEN: The API Token to be included in the API requests.
- LOADBALANCER: The name of the load balancer to retrieve security events for. Set to 'all' to retrieve events for all load balancers.
- PREVIOUS DAYS: How many days you want to extract from today.
- SKIP DAYS: How many days you want to skip for extraction from today.
- VERBOSE: A flag indicating whether to print detailed information about the API request and response.

You can use the `-h` or `--help` option to get the usage information:

```bash
usage: main.py [-h] -t TENANT -k KEY [-n NAMESPACE] [-l LOADBALANCER] [-d PREVIOUS_DAYS] [--skip-days SKIP_DAYS] [-L LIMIT_EVENTS] [-o OUTPUT] [-j] [-V]

F5 XC Security Event Logs Extraction

options:
  -h, --help            show this help message and exit
  -t TENANT, --tenant TENANT
                        Tenant name
  -k KEY, --key KEY     API Token Key
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace ID (Default: "default")
  -l LOADBALANCER, --loadbalancer LOADBALANCER
                        Load Balancer name - If not specified, all LBs will be extracted
  -d PREVIOUS_DAYS, --previous-days PREVIOUS_DAYS
                        Previous days to extract (Default: 7)
  --skip-days SKIP_DAYS
                        Skip previous days to extract (Default: 0)
  -L LIMIT_EVENTS, --limit-events LIMIT_EVENTS
                        Limit the number of events to extract (Default: No limit)
  -o OUTPUT, --output OUTPUT
                        Output file name without extension (Default: "data")
  -j, --json            Output in JSON format. If not specified, the output will be in Excel format
  -V, --verbose         Verbose mode
  -v, --version         Show version
```
