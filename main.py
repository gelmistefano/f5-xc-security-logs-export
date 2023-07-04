"""
F5 XC Security Event Logs Extraction

This script extracts security events from XC (cross-cloud) and saves the data in either Excel or JSON format. It supports various command-line arguments to customize the extraction process.

Usage:
    python script.py [-h] -t TENANT -k KEY [-n NAMESPACE] [-l LOADBALANCER] [-d PREVIOUS_DAYS]
                     [--skip-days SKIP_DAYS] [-L LIMIT_EVENTS] [-o OUTPUT] [-j] [-V]

Arguments:
    -h, --help                Show the help message and exit.
    -t TENANT, --tenant TENANT
                              Specify the name of the tenant for which security events will be extracted. (Required)
    -k KEY, --key KEY         Specify the API token key for authentication. (Required)
    -n NAMESPACE, --namespace NAMESPACE
                              Specify the namespace ID. (Default: "default")
    -l LOADBALANCER, --loadbalancer LOADBALANCER
                              Specify the load balancer name. If not specified, all LBs will be extracted.
    -d PREVIOUS_DAYS, --previous-days PREVIOUS_DAYS
                              Specify the number of previous days to extract. (Default: 7)
    --skip-days SKIP_DAYS     Specify the number of previous days to skip from extraction. (Default: 0)
    -L LIMIT_EVENTS, --limit-events LIMIT_EVENTS
                              Specify the limit on the number of events to extract. (Default: No limit)
    -o OUTPUT, --output OUTPUT
                              Output file name without extension (Default: "data")
    -j, --json                Output the data in JSON format. If not specified, the output will be in Excel format.
    -V, --verbose             Enable verbose mode for detailed logging.

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


def getAggregatedSecEvents(lbs: list) -> list:
  """
    Retrieves aggregated security events for the specified load balancers.

    Parameters:
    - lbs (list): A list of load balancers.

    Returns:
    - List[str]: A list of aggregated security events.

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
    events = getAggregatedSecEvents(lbs)
    for event in events:
        print(event)
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

  # Print API call details if verbose mode is enabled
  if VERBOSE:
    print("Request URL: " + url)
    print("Request headers: " + json.dumps(HEADERS))
    print("Request body: " + json.dumps(requestBody))

  try:
    # Make the API request
    response = requests.post(
        url, headers=HEADERS, json=requestBody)

    response.raise_for_status()  # Raise an exception for non-200 status codes
    data = response.json()

    # Print response details if verbose mode is enabled
    if VERBOSE:
      print("Response code: " + str(response.status_code))
      print("Response content: " + response.text)

    vh_name = []
    for vh in data['aggs']['fieldAggregation_VH_NAME_100']['field_aggregation']['buckets']:
      for lb in lbs:
        if vh['key'].endswith(lb['name']) and not 'redirect-' + lb['name'] in vh['key'] and vh['key'] not in vh_name:
          vh_name.append(vh['key'])

    return vh_name

  except (requests.RequestException, ValueError) as e:
    print("Error GET Security Events: ", e)
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
    response_lb = requests.get(url_lb, headers=HEADERS)
    response_lb.raise_for_status()  # Raise an exception for non-200 status codes
    json_response = response_lb.json()  # Parse the JSON response

    if VERBOSE:
      print("Call API for LBs")
      print("Request URL: " + url_lb)
      print("Request headers: " + json.dumps(HEADERS))
      print("Response code: " + str(response_lb.status_code))
      print("Response content: " + response_lb.text)

    if LOADBALANCER == 'all':
      return json_response['items']
    return [lb for lb in json_response['items'] if lb['name'] == LOADBALANCER]

  except (requests.RequestException, ValueError) as e:
    print("Error GET Load Balancers: ", e)
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
      'query': f'{{"vh_name": "{lb_name}", "sec_event_type":~"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event"}}',
      "aggs": {},
      "scroll": True,
      "start_time": START_TIME,
      "end_time": END_TIME
  }

  # Print API call details if verbose mode is enabled
  if VERBOSE:
    print("Request URL: " + url)
    print("Request headers: " + json.dumps(HEADERS))
    print("Request body: " + json.dumps(requestBody))

  try:
    # Make the API request
    response = requests.post(
        url, headers=HEADERS, json=requestBody) if scroll_id is None else requests.get(url, headers=HEADERS)

    response.raise_for_status()  # Raise an exception for non-200 status codes
    data = response.json()

    # Print response details if verbose mode is enabled
    if VERBOSE:
      print("Response code: " + str(response.status_code))
      print("Response content: " + response.text)
      print("Total Events: " + str(data['total_hits']))

    if data['total_hits'] == 0:
      print("No events found for " + lb_name)
      return []

    if scroll_id is None:
      total_hits = data['total_hits']
      events_gets = 1
      events_gets_to = min(
          LIMIT_EVENTS, total_hits) if LIMIT_EVENTS > 0 else total_hits
    else:
      events_gets = 500 * scroll_number
      total_hits = data['total_hits']
      events_gets_to = min(
          LIMIT_EVENTS, total_hits) if LIMIT_EVENTS > 0 else total_hits

    print("Get events " + str(events_gets) + ' of ' +
          str(events_gets_to) + ' - Total: ' + str(total_hits))

    # Append each event to the list
    for event in data['events']:
      obj.append(json.loads(event))

    # Recursive call if there is a scroll ID present
    scroll_id = data['scroll_id']
    if scroll_id != "":
      next_scroll_num = scroll_number + 1
      num_events_stored = len(obj) + (500 * scroll_number)
      if VERBOSE:
        print('Events now: ' + str(len(obj)))
        print("scroll number: " + str(scroll_number))
        print("Next scroll number: " + str(next_scroll_num))
        print('Next events: ' + str(next_scroll_num * 500))
        print('Events stored: ' + str(num_events_stored))
      if num_events_stored < LIMIT_EVENTS and LIMIT_EVENTS > 0:
        obj_tmp = getSecEvents(lb_name, next_scroll_num, scroll_id)
        obj.extend(obj_tmp)

  except requests.RequestException as e:
    # Print error message and return an empty list
    print('Error requests.RequestException for LB ' + lb_name + ': ' + str(e))
    return []

  except ValueError as e:
    # Print error message and return an empty list
    print('Error ValueError for LB ' + lb_name + ': ' + str(e))
    return []

  return obj


def getSecEvents(lb_name, scroll_number, scroll_id=None):
  obj = []
  url = f'https://{TENANT}.console.ves.volterra.io/api/data/namespaces/{NAMESPACE}/app_security/events'

  end_time = (datetime.utcnow() - timedelta(hours=24 * SKIP_DAYS)
              ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
  start_time = (datetime.utcnow() - timedelta(hours=24 * (DAYS))
                ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

  # Construct the URL with scroll ID if provided
  if scroll_id != None:
    url = url + '/scroll?scroll_id=' + scroll_id
  else:
    # Construct the request body
    requestBody = {
        'namespace': NAMESPACE,
        'query': "{\"vh_name\"=" + lb_name + "\", sec_event_type=~\"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event\"}",
        "aggs": {},
        "scroll": True,
        "start_time": start_time,
        "end_time": end_time
    }

  # Print API call details if verbose mode is enabled
  if VERBOSE:
    print("Request URL: " + url)
    print("Request headers: " + json.dumps(HEADERS))
    print("Request body: " + json.dumps(requestBody))

  try:
    # Make the API request
    response = requests.post(
        url, headers=HEADERS, json=requestBody) if scroll_id == None else requests.get(url, headers=HEADERS)

    # Print response details if verbose mode is enabled
    if VERBOSE:
      print("Response code: " + str(response.status_code))
      print("Response content: " + response.text)
      print("Total Events: " +
            str(json.loads(response.content)['total_hits']))

    if scroll_id == None:
      events_gets = 1
      # 500 is the maximum number of events that can be returned at once
      # if the total number of events is more than 500, then set the number of events to 500
      # unless there is a limit set by the user
      if int(json.loads(response.content)['total_hits']) > 500:
        events_gets_to = 500
      elif LIMIT_EVENTS > 0:
        events_gets_to = LIMIT_EVENTS
      else:
        events_gets_to = int(json.loads(
            response.content)['total_hits'])
    else:
      events_gets = 500 * scroll_number
      if LIMIT_EVENTS > 0 and LIMIT_EVENTS < events_gets + 500:
        events_gets_to = LIMIT_EVENTS
      elif int(json.loads(response.content)['total_hits']) < events_gets + 500:
        events_gets_to = int(json.loads(
            response.content)['total_hits'])
      else:
        events_gets_to = events_gets + 500
    print("Get events " + str(events_gets) + ' of ' + str(events_gets_to) +
          ' - Total: ' + str(json.loads(response.content)['total_hits']))

    if response.status_code == 200:
      # Append each event to the list
      for event in json.loads(response.content)['events']:
        obj.append(json.loads(event))
    else:
      # Print error message and return an empty list
      print('Error for LB ' + lb_name +
            ' - Start Date: ' + start_time +
            ' - End Date: ' + end_time +
            ': ' +
            str(response.status_code) +
            "\n" +
            response.text)
      return []

    # Recursive call if there is a scroll ID present
    if json.loads(response.content)['scroll_id'] != "":
      next_scroll_num = scroll_number + 1
      num_events_stored = int(len(obj)) + (500 * int(scroll_number))
      if VERBOSE:
        print('Events now: ' + str(len(obj)))
        print("scroll number: " + str(scroll_number))
        print("Next scroll number: " + str(next_scroll_num))
        print('Next events: ' + str(next_scroll_num * 500))
        print('Events stored: ' + str(num_events_stored))
      if (num_events_stored) < LIMIT_EVENTS and LIMIT_EVENTS > 0:
        obj_tmp = getSecEvents(lb_name, next_scroll_num, json.loads(
            response.content)['scroll_id'])
        for obj_tmp_item in obj_tmp:
          obj.append(obj_tmp_item)
  except Exception as e:
    # Print error message and return an empty list
    print('Error for LB ' + lb_name +
          str(e))
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
    writer.save()
    writer.close()

    return True

  except Exception as e:
    print("Error Pandas Exception: " + str(e))
    return False


def main():
  """
    Extracts security events from XC for a given tenant.

    Returns:
        None
  """
  print("XC Security Data Extraction")
  print("Extract security events from XC for tenant: {}".format(TENANT))
  print("Namespace: {}".format(NAMESPACE))
  print("Load Balancer: {}".format(LOADBALANCER))
  print("Previous days to extract: {}".format(DAYS))
  print("Skip previous days to extract: {}".format(SKIP_DAYS))
  print("Extract events from: {} to {}".format(START_TIME, END_TIME))
  print("Limit events to extract: {}".format(LIMIT_EVENTS))
  print("Output file name: {}".format(OUTPUTFILE))
  print("\n")

  # Execute API calls to retrieve LBs
  lbs = getLoadBalancers()
  if len(lbs) == 0:
    print("No LBs found for tenant: {}\nExiting...".format(TENANT))
    exit(1)

  vh_name = getAggregatedSecEvents(lbs)
  if len(vh_name) == 0:
    print("No VHs found for tenant: {}\nExiting...".format(TENANT))
    exit(1)

  if VERBOSE:
    print("Request all LBs") if LOADBALANCER == 'all' else print(
        "Request LB: {}".format(LOADBALANCER))
    print(json.dumps(lbs, indent=2))
    print("\n")
    print("Request all VHs") if LOADBALANCER == 'all' else print("Request VH")
    print(json.dumps(vh_name, indent=2))

  obj_events = {}
  for vh in vh_name:
    print("Request events for LB: {}".format(vh))
    obj_events[vh] = getSecEvents(vh, 0)

  if len(obj_events) == 0:
    print("No events found for tenant: {}\nExiting...".format(TENANT))
    exit(1)

  supported_event_types = {
    'waf_sec_event', 'bot_defense_sec_event', 'api_sec_event', 'svc_policy_sec_event'}
  obj_events_saved = {event_type: [] for event_type in supported_event_types}

  for _, events in obj_events.items():
    for event in events:
      event_type = event['sec_event_type']
      if event_type not in supported_event_types:
        print("Event type {} not supported".format(event_type))
        break
      obj_events_saved[event_type].append(event)

  print("Extracted events: {}".format(len(obj_events)))
  for key, value in obj_events_saved.items():
    print("Extracted events with type {}: {}".format(key, len(value)))
  print("\n")

  print("Save data in file: {}".format(OUTPUTFILE))
  resulSave = saveToJSON(
    obj_events_saved) if IS_JSON else saveToExcel(obj_events_saved)
  if resulSave:
    print("Data saved successfully!")


# Create an argument parser
parser = argparse.ArgumentParser(
  description='F5 XC Security Event Logs Extraction')

# Add the arguments you want to receive from the CLI
parser.add_argument('-t', '--tenant', type=str,
                    required=True, help='Tenant name')
parser.add_argument('-k', '--key', type=str,
                    required=True, help='API Token Key')
parser.add_argument('-n', '--namespace', type=str,
                    default='default', help='Namespace ID (Default: "default")')
parser.add_argument('-l', '--loadbalancer', type=str,
                    help='Load Balancer name - If not specified, all LBs will be extracted')
parser.add_argument('-d', '--previous-days', type=int, default=7,
                    help='Previous days to extract (Default: 7)')
parser.add_argument('--skip-days', type=int, default=0,
                    help='Skip previous days to extract (Default: 0)')
parser.add_argument('-L', '--limit-events', type=int, default=0,
                    help='Limit the number of events to extract (Default: No limit)')
parser.add_argument('-o', '--output', type=str, default='data',
                    help='Output file name without extension (Default: "data")')
parser.add_argument('-j', '--json', action='store_true',
                    help='Output in JSON format. If not specified, the output will be in Excel format')
parser.add_argument('-V', '--verbose', action='store_true', help='Verbose mode')
parser.add_argument('-v', '--version', action='version', help='Show version',
                    version='F5 XC Security Event Logs Extraction 1.0.0 - By: @gelmistefano')


# Parse the arguments from CLI
args = parser.parse_args()

# Use the provided arguments or default values
TENANT = args.tenant
NAMESPACE = args.namespace
DAYS = args.previous_days
OUTPUT_FORMAT = 'json' if args.json else 'xlsx'
OUTPUTFILE = args.output + '.' + OUTPUT_FORMAT
LOADBALANCER = args.loadbalancer
SKIP_DAYS = args.skip_days
LIMIT_EVENTS = args.limit_events
VERBOSE = args.verbose
HEADERS = {'Authorization': 'APIToken ' + args.key,
           'Content-type': 'application/json', 'accept': 'application/json'}
END_TIME = (datetime.utcnow() - timedelta(hours=24 * SKIP_DAYS)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
START_TIME = (datetime.utcnow() - timedelta(hours=24 * DAYS)
              ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
IS_JSON = args.json

# Main function
main()
