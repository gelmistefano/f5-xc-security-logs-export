"""
F5 XC Security Event Logs Extraction

This script extracts security events from XC (cross-cloud) and saves the data in either Excel or JSON format. It supports various command-line arguments to customize the extraction process.

usage: 
  main.py [-h] -t TENANT -k KEY [-n NAMESPACE] [-l LOADBALANCER] [-d PREVIOUS_DAYS] [--skip-days SKIP_DAYS] [-L LIMIT_EVENTS] [-o OUTPUT] [-j] [-F FROM_DATE] [-T TO_DATE] [-V] [-v]

F5 XC Security Event Logs Extraction. Extract security logs from XC for a given tenant and save them to a JSON or Excel file.

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
  -F FROM_DATE, --from-date FROM_DATE
                        From date in format YYYY-MM-DD[THH:MM:SS] (if you use --previous-days, this date will be ignored)
  -T TO_DATE, --to-date TO_DATE
                        To date in format YYYY-MM-DD[THH:MM:SS] (if you use --previous-days, this date will be ignored)
  -V, --verbose         Verbose mode
  -v, --version         Show version
Examples:
    python script.py -t MyTenant -k MyApiKey
    python script.py -t MyTenant -k MyApiKey -n MyNamespace -l MyLoadBalancer -d 10 --skip-days 2 -L 100 -o mydata -j -V

Note:
    - The script requires the 'argparse' library to be installed. You can install it via 'pip install argparse'.
    - TENANT and KEY are required arguments.
"""

import os
import requests
import json
import pandas as pd
from datetime import datetime, timedelta
import argparse
from dateutil.parser import parse
import sys

RECUSION_LIMIT = 5000


class recursion_depth:
  def __init__(self, limit):
    self.limit = limit
    self.default_limit = sys.getrecursionlimit()

  def __enter__(self):
    sys.setrecursionlimit(self.limit)

  def __exit__(self, type, value, traceback):
    sys.setrecursionlimit(self.default_limit)


def sendXCGetsRequest(url: str) -> dict:
  # Print API call details if verbose mode is enabled
  if VERBOSE:
    print(f"Request URL: {url}")
    print(f"Request headers: {json.dumps(HEADERS, indent=2)}")

  try:
    response_lb = requests.get(url, headers=HEADERS)
    response_lb.raise_for_status()  # Raise an exception for non-200 status codes
    data = response_lb.json()  # Parse the JSON response

    if VERBOSE:
      print(f"Response code: {response_lb.status_code}")
      print(f"Response content: {response_lb.text}")

    return data

  except (requests.RequestException) as e:
    print(f"Error GET Request: {e}")
    raise


def sendXCPostRequest(url: str, requestBody: dict) -> dict:
  # Print API call details if verbose mode is enabled
  if VERBOSE:
    print(f"Request URL: {url}")
    print(f"Request headers: {json.dumps(HEADERS, indent=2)}")
    print(f"Request body: {json.dumps(requestBody, indent=2)}")

  try:
    # Make the API request
    response = requests.post(
        url, headers=HEADERS, json=requestBody)

    response.raise_for_status()  # Raise an exception for non-200 status codes
    data = response.json()

    # Print response details if verbose mode is enabled
    if VERBOSE:
      print(f"Response code: {response.status_code}")
      print(f"Response content: {response.text}")

    return data

  except (requests.RequestException, ValueError, Exception) as e:
    print(f"Error POST Request: {e}")
    raise


def getVirtualHostname(lbs: list) -> list:
  """
    Retrieves getVirtualHostname from aggregated security events.

    Parameters:
    - lbs (list): A list of load balancers.

    Returns:
    - List[str]: A list of Virtual Hostnames that match LBs name.

    Raises:
    - requests.RequestException: If an error occurs while making the API request.
    - ValueError: If there is an issue with the provided parameters or response parsing.

    Note:
    - The function makes use of the following global variables:
      - TENANT: The tenant information for constructing the API URL.
      - NAMESPACE: The namespace information for constructing the API URL.
      - VERBOSE: A flag indicating whether to print detailed information about the API request and response.
      - HEADERS: The headers to be included in the API request.
      - START_TIME: The start time for retrieving security events.
      - END_TIME: The end time for retrieving security events.

    Example usage:
    ```
    lbs = [{'name': 'lb1'}, {'name': 'lb2'}]
    vh_names = getVirtualHostname(lbs)
    for vh_name in vh_names:
        print(vh_name)
    ```
  """

  url = f'https://{TENANT}.console.ves.volterra.io/api/data/namespaces/{NAMESPACE}/app_security/events/aggregation'
  if VERBOSE:
    print("Execute API calls to retrieve LBs VH_NAME")

  # Construct the request body
  requestBody = {
      'namespace': NAMESPACE,
      'query': '{sec_event_type=~"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event"}',
      'aggs': {
        'fieldAggregation_VH_NAME_100': {
            'field_aggregation': {
                'field': 'VH_NAME',
                'topk': 100
            }
        }
      },
      "start_time": START_TIME,
      "end_time": END_TIME,
  }

  try:
    data = sendXCPostRequest(url, requestBody)
    vh_name = []
    for vh in data['aggs']['fieldAggregation_VH_NAME_100']['field_aggregation']['buckets']:
      for lb in lbs:
        if vh['key'].endswith(lb['name']) and not 'redirect-' + lb['name'] in vh['key'] and vh['key'] not in vh_name:
          vh_name.append(vh['key'])

    return vh_name

  except (requests.RequestException, ValueError, Exception) as e:
    print(f"Error GET Security Events: {e}")
    return []


def getLoadBalancers() -> list:
  """
    Retrieves load balancers from a specified URL.

    Returns a list of load balancers based on certain conditions.

    Parameters:
    None

    Returns:
    - If the HTTP response status code is 200 (OK):
      - If the LOADBALANCER variable is set to 'all', returns a list of all load balancers obtained from the JSON response.
      - If the LOADBALANCER variable is set to a specific load balancer name, returns a list containing only the load balancer with that name from the JSON response.
    - If the HTTP response status code is not 200, returns an empty list.
  """

  # Get Load Balancers
  url_lb = f'https://{TENANT}.console.ves.volterra.io/api/config/namespaces/{NAMESPACE}/http_loadbalancers'

  if VERBOSE:
    print("Execute API calls to retrieve LBs")
  try:
    json_response = sendXCGetsRequest(url_lb)

    if LOADBALANCER == 'all':
      return json_response['items']
    return [lb for lb in json_response['items'] if lb['name'] == LOADBALANCER]

  except (requests.RequestException, ValueError, Exception) as e:
    print(f"Error GET Load Balancers: {e}")
    return []


def getSecEvents(lb_name: str, scroll_number: int, scroll_id: str | None = None) -> list:
  """
  Retrieves security events for a specified load balancer.

  Parameters:
  - lb_name (str): The name of the load balancer.
  - scroll_number (int): The scroll number for pagination. Starts from 0.
  - scroll_id (str | None, optional): The scroll ID for fetching subsequent pages. Defaults to None.

  Returns:
  - List[Dict[Any]]: A list of security events for the load balancer.

  Raises:
  - requests.RequestException: If an error occurs while making the API request.
  - ValueError: If there is an issue with the provided parameters or response parsing.

  Note:
  - The function makes use of the following global variables:
    - TENANT: The tenant information for constructing the API URL.
    - NAMESPACE: The namespace information for constructing the API URL.
    - HEADERS: The headers to be included in the API request.
    - VERBOSE: A flag indicating whether to print detailed information about the API request and response.
    - SKIP_DAYS: The number of days to skip when calculating the start time for event retrieval.
    - DAYS: The number of days to include when calculating the start time for event retrieval.
    - LIMIT_EVENTS: The maximum number of events to retrieve (0 means no limit).

  Example usage:
  ```
    events = getSecEvents('my_lb', 1)
    for event in events:
    print(event)
  ```
  """
  obj = []
  url = f'https://{TENANT}.console.ves.volterra.io/api/data/namespaces/{NAMESPACE}/app_security/events'

  # Construct the URL with scroll ID if provided
  if scroll_id is not None:
    url = f'{url}/scroll?scroll_id={scroll_id}'

  # Construct the request body
  requestBody = {
      'namespace': NAMESPACE,
      'query': f'{{vh_name="{lb_name}", sec_event_type=~"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event"}}',
      "aggs": {},
      "scroll": True,
      "start_time": START_TIME,
      "end_time": END_TIME
  }

  try:
    # Make the API request
    data = sendXCPostRequest(
      url, requestBody) if scroll_id is None else sendXCGetsRequest(url)

    if VERBOSE:
      print(f"Total Events: {(data['total_hits'])}")

    if data['total_hits'] == 0:
      print(f"No events found for {lb_name}")
      return []

    total_hits = int(data['total_hits'])
    events_gets_to = len(data['events']) if scroll_id is None else len(
      data['events']) + 500 * scroll_number
    total_events = total_hits if LIMIT_EVENTS == 0 else LIMIT_EVENTS

    print(
      f"Request #{scroll_number + 1}: Got {events_gets_to} events of {total_events}")

    # Append each event to the list
    for event in data['events']:
      obj.append(json.loads(event))

    # Recursive call if there is a scroll ID present
    scroll_id = data['scroll_id']
    if scroll_id != "":
      next_scroll_num = scroll_number + 1
      num_events_stored = len(obj) + (500 * scroll_number)
      if VERBOSE:
        print(f'Events now: {len(obj)}')
        print(f"scroll number: {scroll_number}")
        print(f"Next scroll number: {next_scroll_num}")
        print(f'Next events: {next_scroll_num * 500}')
        print(f'Events stored: {num_events_stored}')
        print(f'Limit events: {LIMIT_EVENTS}')
      if (num_events_stored < LIMIT_EVENTS and LIMIT_EVENTS > 0) or num_events_stored < total_hits:
        obj_tmp = getSecEvents(lb_name, next_scroll_num, scroll_id)
        obj.extend(obj_tmp)

  except (requests.RequestException, ValueError, Exception) as e:
    # Print error message and return an empty list
    print(f'Error Exception for LB {lb_name}: {e}')
    return []

  return obj


def saveToJSON(data: list):
  """
  Save a list to a JSON file.

  Parameters:
  - data: The list to be saved.
  - file_path: The path to the JSON file.

  Note:
  - The function makes use of the following global variables:
    - OUTPUTFILE: The path to the JSON file.

  Returns:
  - bool: True if the list was successfully saved to the file, False otherwise.
  """
  try:
    file_path = os.path.join(os.getcwd(), OUTPUTFILE)
    with open(file_path, 'w') as file:
      json.dump(data, file)
    return True
  except Exception as e:
    print(f"Error saving list to JSON file: {e}")
    return False


def saveToExcel(data: dict) -> bool:
  """
    Save the data to an Excel file.

    Parameters:
    - data (dict): A dictionary containing event data for different event types.

    Returns:
    - bool: True if the data is successfully saved, False otherwise.

    Raises:
    - Exception: If there is an error during the saving process.

  """

  try:
      # Create a writer for the Excel file
    writer = pd.ExcelWriter(OUTPUTFILE)

    for sheet, events in data.items():
      # Create a DataFrame for each sheet
      df = pd.DataFrame(events)

      # Write the DataFrame to the sheet in the Excel file
      df.to_excel(writer, sheet_name=sheet, index=False)

    # Save the Excel file
    writer.close()

    return True

  except Exception as e:
    print(f"Error Pandas Exception: {e}")
    return False


def main():
  """
    Extracts security events from XC for a given tenant.

    Returns:
        None
  """
  print("XC Security Data Extraction")
  print(f"Extract security events from XC for tenant: {TENANT}")
  print(f"Namespace: {NAMESPACE}")
  print(f"Load Balancer: {LOADBALANCER}")
  print(
    f"Extract events from: {datetime.strptime(START_TIME, DATE_FORMAT):%d/%m/%Y %H:%M:%S}")
  print(
    f"Extract events to  : {datetime.strptime(END_TIME, DATE_FORMAT):%d/%m/%Y %H:%M:%S}")
  print("Limit events to extract: {}".format(
    LIMIT_EVENTS if LIMIT_EVENTS > 0 else "No limit"))
  print(f"Output file name: {OUTPUTFILE}")
  print("\n")

  # Execute API calls to retrieve LBs
  lbs = getLoadBalancers()
  if len(lbs) == 0:
    print(f"No LBs found for tenant: {TENANT}\nExiting...")
    exit(1)

  vh_name = getVirtualHostname(lbs)
  if len(vh_name) == 0:
    print(f"No VHs found for tenant: {TENANT}\nExiting...")
    exit(1)

  if VERBOSE:
    print("Request all LBs") if LOADBALANCER == 'all' else print(
        "Request LB: {LOADBALANCER}")
    print(f"Load Balancers list: {json.dumps(lbs, indent=2)}")
    print("\n")
    print("Request all VHs") if LOADBALANCER == 'all' else print("Request VH")
    print(f"Virtual Host list: {json.dumps(vh_name, indent=2)}")

  obj_events = {}
  for vh in vh_name:
    print(f"Request events for LB: {vh}")
    with recursion_depth(RECUSION_LIMIT):
      obj_events[vh] = getSecEvents(vh, 0)

  if len(obj_events) == 0:
    print(f"No events found for tenant: {TENANT}\nExiting...")
    exit(1)

  supported_event_types = {
    'waf_sec_event', 'bot_defense_sec_event', 'api_sec_event', 'svc_policy_sec_event'}
  obj_events_saved = {event_type: [] for event_type in supported_event_types}

  for _, events in obj_events.items():
    for event in events:
      event_type = event['sec_event_type']
      if event_type not in supported_event_types:
        print(f"Event type {event_type} not supported")
        break
      obj_events_saved[event_type].append(event)

  for key, value in obj_events_saved.items():
    print(f"Extracted events with type {key}: {len(value)}")
  print("\n")

  print(f"Save data in file: {OUTPUTFILE}")
  resulSave = saveToJSON(
    obj_events_saved) if IS_JSON else saveToExcel(obj_events_saved)
  if resulSave:
    print("Data saved successfully!")


# Create an argument parser
parser = argparse.ArgumentParser(
  description='F5 XC Security Event Logs Extraction.\nExtract security logs from XC for a given tenant and save them to a JSON or Excel file.')

# Add the arguments you want to receive from the CLI
parser.add_argument('-t', '--tenant', type=str,
                    required=True, help='Tenant name')
parser.add_argument('-k', '--key', type=str,
                    required=True, help='API Token Key')
parser.add_argument('-n', '--namespace', type=str,
                    default='default', help='Namespace ID (Default: "default")')
parser.add_argument('-l', '--loadbalancer', type=str,
                    help='Load Balancer name - If not specified, all LBs will be extracted')
parser.add_argument('-d', '--previous-days', type=int,
                    help='Previous days to extract (Default: 7)')
parser.add_argument('--skip-days', type=int, default=0,
                    help='Skip previous days to extract (Default: 0)')
parser.add_argument('-L', '--limit-events', type=int,
                    help='Limit the number of events to extract (Default: No limit)')
parser.add_argument('-o', '--output', type=str, default='data',
                    help='Output file name without extension (Default: "data")')
parser.add_argument('-j', '--json', action='store_true',
                    help='Output in JSON format. If not specified, the output will be in Excel format')
parser.add_argument('-F', '--from-date', type=str,
                    help='From date in format YYYY-MM-DD[THH:MM:SS] (if you use --previous-days, this date will be ignored)')
parser.add_argument('-T', '--to-date', type=str,
                    help='To date in format YYYY-MM-DD[THH:MM:SS] (if you use --previous-days, this date will be ignored)')
parser.add_argument('-V', '--verbose', action='store_true', help='Verbose mode')
parser.add_argument('-v', '--version', action='version', help='Show version',
                    version='F5 XC Security Event Logs Extraction 1.0.0 - By: @gelmistefano')

# Parse the arguments from CLI
args = parser.parse_args()

# Use the provided arguments or default values
TENANT: str = args.tenant
NAMESPACE: str = args.namespace
IS_JSON: bool = args.json
OUTPUT_FORMAT: str = 'json' if IS_JSON else 'xlsx'
OUTPUTFILE: str = args.output + '.' + OUTPUT_FORMAT
LOADBALANCER: str = args.loadbalancer or 'all'
DAYS: int = args.previous_days if args.previous_days is not None else 7
SKIP_DAYS: int = args.skip_days if args.skip_days is not None else 0
LIMIT_EVENTS: int = args.limit_events or 0
VERBOSE: bool = args.verbose
HEADERS = {'Authorization': 'APIToken ' + args.key,
           'Content-type': 'application/json', 'accept': 'application/json'}
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
try:
  if args.from_date is not None:
    START_TIME = parse(args.from_date, ignoretz=True).strftime(DATE_FORMAT)
  else:
    START_TIME = (datetime.utcnow() - timedelta(hours=24 *
                  DAYS)).strftime(DATE_FORMAT)
  if args.to_date is not None:
    END_TIME = parse(args.to_date, ignoretz=True).strftime(DATE_FORMAT)
  else:
    END_TIME = (datetime.utcnow() - timedelta(hours=24 * SKIP_DAYS)
                ).strftime(DATE_FORMAT)
except ValueError as e:
  print("Invalid from date format, should be YYYY-MM-DD[THH:MM:SS]. Exiting...")
  exit(1)

# Main function
main()
