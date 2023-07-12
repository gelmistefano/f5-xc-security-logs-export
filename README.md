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
- PREVIOUS DAYS: How many days you want to extract from today. If you use `FROM_DATE` argument, this argument will be ignored.
- SKIP DAYS: How many days you want to skip for extraction from today. If you use `TO_DATE` argument, this argument will be ignored.
- LIMIT EVENTS: The maximum number of events to extract. Set to 0 for no limit. _(See Known Issue for events limit)_
- FROM_DATE (in datetime format: YYYY-MM-DD[THH:MM:SS]): The start date to extract events from.
- TO_DATE (in datetime format: YYYY-MM-DD[THH:MM:SS]): The end date to extract events to.
- VERBOSE: A flag indicating whether to print detailed information about the API request and response.

You can use the `-h` or `--help` option to get the usage information:

```bash
usage: main.py [-h] -t TENANT -k API_KEY [-n NAMESPACE] [-l LOADBALANCER] [-d PREVIOUS_DAYS] [--skip-days SKIP_DAYS] [-L LIMIT_EVENTS] [-o OUTPUT] [-j] [-F FROM_DATE] [-T TO_DATE] [-v] [--version]

F5 XC Security Event Logs Extraction. Extract security logs from XC for a given tenant and save them to a JSON or Excel file.

options:
  -h, --help            show this help message and exit
  -t TENANT, --tenant TENANT
                        Tenant name
  -k API_KEY, --api-key API_KEY
                        API Token Key
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace ID (Default: "default")
  -l LOADBALANCER, --loadbalancer LOADBALANCER
                        Load Balancer name - If not specified, all LBs will be extracted
  -d PREVIOUS_DAYS, --previous-days PREVIOUS_DAYS
                        Previous days to extract (Default: 7 - if you use --from-date, this argument will be ignored)
  --skip-days SKIP_DAYS
                        Skip previous days to extract (Default: 0 - if you use --to-date, this argument will be ignored)
  -L LIMIT_EVENTS, --limit-events LIMIT_EVENTS
                        Limit the number of events to extract (Default: No limit)
  -o OUTPUT, --output OUTPUT
                        Output file name without extension (Default: "data")
  -j, --json            Output in JSON format. If not specified, the output will be in Excel format
  -F FROM_DATE, --from-date FROM_DATE
                        From date in format YYYY-MM-DD[THH:MM:SS]
  -T TO_DATE, --to-date TO_DATE
                        To date in format YYYY-MM-DD[THH:MM:SS]
  -v, --verbose         Verbose mode
  --version             Show version
```

## Known Issues

- If the events to be exported are too many, the script may fail with the following error:

```bash
RecursionError: maximum recursion depth exceeded while calling a Python object
```

This is a known issue. To fix this, you need to increase the recursion limit by increase the `RECURSION_LIMIT` variable to the beginning of the script. The default value is 5000 (2.5M events).
