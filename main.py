"""
F5 XC Security Event Logs Extraction

This script extracts security events from XC (cross-cloud) and saves the data in either Excel or JSON format. It supports various command-line arguments to customize the extraction process.

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
Examples:
    python script.py -t MyTenant -k MyApiKey
    python script.py -t MyTenant -k MyApiKey -n MyNamespace -l MyLoadBalancer -d 10 --skip-days 2 -L 100 -o mydata -j -V

Note:
    - The script requires the 'argparse' library to be installed. You can install it via 'pip install argparse'.
    - TENANT and KEY are required arguments.
"""

import json
import sys
import argparse
from datetime import datetime, timedelta

import utils
from XC import XC

RECUSION_LIMIT = 5000


class recursion_depth:
  def __init__(self, limit):
    self.limit = limit
    self.default_limit = sys.getrecursionlimit()

  def __enter__(self):
    sys.setrecursionlimit(self.limit)

  def __exit__(self, type, value, traceback):
    sys.setrecursionlimit(self.default_limit)


def exit_script(exit_code: int = 0) -> None:
  """Print current datetime and exit from this script with the provided exit code.

  Args:
      exit_code (int, optional): _description_. Defaults to 0.
  """
  print(f"\n### END SCRIPT: {datetime.now():%d/%m/%Y %H:%M:%S} ###\n")
  exit(exit_code)


def main() -> None:
  """
    Extracts security events from XC for a given tenant.

    Returns:
        None
  """
  DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

  args = args_parser()

  # Use the provided arguments or default values
  IS_JSON: bool = args.json
  OUTPUT_FILE: str = '{}.{}'.format(args.output, 'json' if IS_JSON else 'xlsx')
  previous_days: int = args.previous_days or 7
  skip_days: int = args.skip_days or 0
  verbose: bool = args.verbose

  # Generate dates
  start_time = args.from_date or (datetime.utcnow() - timedelta(hours=24 * previous_days))
  end_time = args.to_date or (datetime.utcnow() - timedelta(hours=24 * skip_days))

  # Create XC object
  try:
    xc = XC(args.tenant, args.namespace, args.api_key, args.loadbalancer, start_time, end_time, args.limit_events)
  except (ValueError, Exception) as e:
    print(e)
    exit_script(1)

  # Print summary
  print("XC Security Data Extraction")
  print(f"Extract security events from XC for tenant: {xc.tenant}")
  print(f"Namespace: {xc.namespace}")
  print(f"Load Balancer: {xc.loadbalancer_name}")
  print(f"Extract events from: {xc.get_start_date_datetime():%d/%m/%Y %H:%M:%S}")
  print(f"Extract events to  : {xc.get_to_date_datetime():%d/%m/%Y %H:%M:%S}")
  print("Limit events to extract: {}".format(xc.limit_events if xc.limit_events > 0 else "No limit"))
  print(f"Output file name: {OUTPUT_FILE}")
  print(f"\n### START SCRIPT: {datetime.now():%d/%m/%Y %H:%M:%S} ###\n")

  # Execute API calls to retrieve LBs
  lbs = xc.get_all_loadbalancers(verbose)
  if len(lbs) == 0:
    print(f"No LBs found for tenant: {xc.tenant}\nExiting...")
    exit_script(1)

  vh_name = xc.get_virtual_hostname(lbs, verbose)
  if len(vh_name) == 0:
    print(f"No VHs found for tenant: {xc.tenant}\nExiting...")
    exit_script(1)

  lb_names = [lb['name'] for lb in lbs]

  print(f"Requested LBs: {', '.join(lb_names)}")
  print(f"Requested VHs with security policy: {', '.join(vh_name)}")

  if verbose:
    print(f"Load Balancers list: {json.dumps(lbs, indent=2)}")

  print("\n")

  obj_events = {}
  for vh in vh_name:
    print(f"Request events for LB: {vh}")
    with recursion_depth(RECUSION_LIMIT):
      obj_events[vh] = xc.get_security_events(vh, 0, None, verbose)

  if len(obj_events) == 0:
    print(f"No events found for tenant: {xc.tenant}\nExiting...")
    exit_script(1)

  # Finish collecting data - Start Write to file

  supported_event_types = {'waf_sec_event', 'bot_defense_sec_event', 'api_sec_event', 'svc_policy_sec_event'}
  obj_events_saved = {event_type: [] for event_type in supported_event_types}

  # Select only supported event types - Separate in different lists
  for _, events in obj_events.items():
    for event in events:
      event_type = event['sec_event_type']
      if event_type not in supported_event_types:
        print(f"Event type {event_type} not supported")
        break
      obj_events_saved[event_type].append(event)

  print("\n")
  for key, value in obj_events_saved.items():
    print(f"Extracted events with type {key}: {utils.get_string_number(len(value))}")
  print("\n")

  if all(len(lst) == 0 for lst in obj_events_saved.values()):
    print(f"No events found for tenant: {xc.tenant}\nExiting...")
    exit_script(1)

  print(f"Save data in file: {OUTPUT_FILE}")
  if IS_JSON:
    resultSave = utils.saveToJSON(obj_events_saved, OUTPUT_FILE)
  else:
    resultSave = utils.saveToExcel(obj_events_saved, OUTPUT_FILE)

  if resultSave:
    print("Data saved successfully!")
    exit_script()


def args_parser() -> object:
  """
    Create an argument parser and parse the arguments from CLI.

    Returns:
    - Args object
  """
  # Create an argument parser
  parser = argparse.ArgumentParser(
    description='F5 XC Security Event Logs Extraction.\nExtract security logs from XC for a given tenant and save them to a JSON or Excel file.')

  # Add the arguments you want to receive from the CLI
  parser.add_argument('-t', '--tenant', type=str,
                      required=True, help='Tenant name')
  parser.add_argument('-k', '--api-key', type=str,
                      required=True, help='API Token Key')
  parser.add_argument('-n', '--namespace', type=str,
                      default='default', help='Namespace ID (Default: "default")')
  parser.add_argument('-l', '--loadbalancer', type=str,
                      help='Load Balancer name - If not specified, all LBs will be extracted')
  parser.add_argument('-d', '--previous-days', type=int,
                      help='Previous days to extract (Default: 7 - if you use --from-date, this argument will be ignored)')
  parser.add_argument('--skip-days', type=int, default=0,
                      help='Skip previous days to extract (Default: 0 - if you use --to-date, this argument will be ignored)')
  parser.add_argument('-L', '--limit-events', type=int,
                      help='Limit the number of events to extract (Default: No limit)')
  parser.add_argument('-o', '--output', type=str, default='data',
                      help='Output file name without extension (Default: "data")')
  parser.add_argument('-j', '--json', action='store_true',
                      help='Output in JSON format. If not specified, the output will be in Excel format')
  parser.add_argument('-F', '--from-date', type=str,
                      help='From date in format YYYY-MM-DD[THH:MM:SS]')
  parser.add_argument('-T', '--to-date', type=str,
                      help='To date in format YYYY-MM-DD[THH:MM:SS]')
  parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
  parser.add_argument('--version', action='version', help='Show version',
                      version='F5 XC Security Event Logs Extraction 1.0.0 - By: @gelmistefano')

  # Parse the arguments from CLI
  return parser.parse_args()


# Main function
main()
