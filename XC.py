import json
from requests import RequestException
from datetime import datetime
from dateutil.parser import parse


from utils import send_post_request, send_get_request, get_string_number


class XC:
  """
  Class representing an XC object with its attributes and methods. Used to set up the XC object and retrieve data from the XC API.
  """

  def __init__(self, tenant: str, namespace: str, api_key: str, loadbalancer_name: str | None, start_date: str | datetime, to_date: str | datetime, limit_events: int | None):
    """
    Initializes a new instance of the class XC.

    Args:
      - tenant (str): The name of the tenant.
      - namespace (str): The namespace.
      - api_key (str): The API key.
      - loadbalancer_name (str | None): The name of the load balancer, or 'all' if None.
      - start_date (str | datetime): The start date of the events range.
      - to_date (str | datetime): The end date of the events range.
      - limit_events (int | None): The maximum number of events to retrieve, or 0 if None.
    """
    self._tenant = tenant
    self._namespace = namespace
    self._api_key = api_key
    self._loadbalancer_name = loadbalancer_name or 'all'
    self._limit_events = limit_events or 0
    self.__DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
    try:
      if type(to_date) is datetime:
        self._to_date = to_date.strftime(self.__DATETIME_FORMAT)
      else:
        self._to_date = parse(to_date, ignoretz=True).strftime(self.__DATETIME_FORMAT)
      if type(start_date) is datetime:
        self._start_date = start_date.strftime(self.__DATETIME_FORMAT)
      else:
        self._start_date = parse(start_date, ignoretz=True).strftime(self.__DATETIME_FORMAT)
    except ValueError:
      raise ValueError("Invalid from date format, should be YYYY-MM-DD[THH:MM:SS]. Exiting...")
    except Exception as e:
      raise Exception(f'Generic Error during class init: {e}')

  @property
  def tenant(self) -> str:
    """
    Get the value of the tenant.

    Returns:
      str: The tenant.
    """
    return self._tenant

  @property
  def namespace(self) -> str:
    """
    Get the value of the namespace.

    Returns:
      str: The namespace.
    """
    return self._namespace

  @property
  def api_key(self) -> str:
    """
    Get the value of the API key.

    Returns:
      str: The API key.
    """
    return self._api_key

  @property
  def loadbalancer_name(self) -> str:
    """
    Get the value of the load balancer name.

    Returns:
      str: The load balancer name.
    """
    return self._loadbalancer_name

  @property
  def start_date(self) -> str:
    """
    Get the value of the start date.

    Returns:
      str: The start date.
    """
    return self._start_date

  @property
  def to_date(self) -> str:
    """
    Get the value of the end date.

    Returns:
      str: The end date.
    """
    return self._to_date

  @property
  def limit_events(self) -> int:
    """
    Get the value of the limit events.

    Returns:
      int: The limit events.
    """
    return self._limit_events

  def get_to_date_datetime(self) -> datetime:
    """
    Get the end date as a datetime object.

    Returns:
      datetime: The end date as a datetime object.
    """
    return datetime.strptime(self._to_date, self.__DATETIME_FORMAT)

  def get_start_date_datetime(self) -> datetime:
    """
    Get the start date as a datetime object.

    Returns:
      datetime: The start date as a datetime object.
    """
    return datetime.strptime(self._start_date, self.__DATETIME_FORMAT)

  @tenant.setter
  def set_tenant(self, tenant: str):
    """
    Set the value of the tenant.

    Args:
      tenant (str): The tenant.
    """
    self._tenant = tenant

  @namespace.setter
  def set_namespace(self, namespace: str):
    """
    Set the value of the namespace.

    Args:
      namespace (str): The namespace.
    """
    self._namespace = namespace

  @loadbalancer_name.setter
  def set_loadbalancer_name(self, loadbalancer_name: str):
    """
    Set the value of the load balancer name.

    Args:
      loadbalancer_name (str): The load balancer name.
    """
    self._loadbalancer_name = loadbalancer_name

  @api_key.setter
  def set_api_key(self, api_key: str):
    """
    Set the value of the API key.

    Args:
      api_key (str): The API key.
    """
    self._api_key = api_key

  @start_date.setter
  def set_start_date(self, start_date: str):
    """
    Set the value of the start date.

    Args:
      start_date (str): The start date.
    """
    self._start_date = start_date

  @to_date.setter
  def set_to_date(self, to_date: str):
    """
    Set the value of the end date.

    Args:
      to_date (str): The end date.
    """
    self._to_date = to_date

  @limit_events.setter
  def set_limit_events(self, limit_events: int):
    """
    Set the value of the limit events.

    Args:
      limit_events (int): The limit events.
    """
    self._limit_events = limit_events

  def set_to_date_from_datetime(self, datetime_to_date: datetime):
    """
    Set the end date from a datetime object.

    Args:
      datetime_to_date (datetime): The end date as a datetime object.
    """
    self._to_date = datetime_to_date.strftime(self.__DATETIME_FORMAT)

  def set_start_date_from_datetime(self, datetime_start_date: datetime):
    """
    Set the start date from a datetime object.

    Args:
      datetime_start_date (datetime): The start date as a datetime object.
    """
    self._start_date = datetime_start_date.strftime(self.__DATETIME_FORMAT)

  # Methods

  def get_virtual_hostname(self, lbs: list, verbose: bool = False) -> list:
    """
      Retrieves Virtual Hostname values from aggregated security events.

      Parameters:
      - lbs (list): A list of load balancers.
      - verbose (bool, optional): A boolean value to enable/disable verbose mode. Defaults to False.

      Returns:
      - List[str]: A list of Virtual Hostnames that match LBs name.

      Raises:
      - requests.RequestException: If an error occurs while making the API request.
      - ValueError: If there is an issue with the provided parameters or response parsing.
      - Exception: If an unexpected error occurs.
    """

    url = f'https://{self.tenant}.console.ves.volterra.io/api/data/namespaces/{self.namespace}/app_security/events/aggregation'
    if verbose:
      print("Execute API calls to retrieve LBs VH_NAME")

    # Construct the request body
    requestBody = {
        'namespace': self.namespace,
        'query': '{sec_event_type=~"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event"}',
        'aggs': {
          'fieldAggregation_VH_NAME_100': {
              'field_aggregation': {
                  'field': 'VH_NAME',
                  'topk': 100
              }
          }
        },
        "start_time": self.start_date,
        "end_time": self.to_date,
    }

    try:
      data = send_post_request(url, requestBody, self.api_key, verbose)
      vh_name = []
      for vh in data['aggs']['fieldAggregation_VH_NAME_100']['field_aggregation']['buckets']:
        for lb in lbs:
          if vh['key'].endswith(lb['name']) and not 'redirect-' + lb['name'] in vh['key'] and vh['key'] not in vh_name:
            vh_name.append(vh['key'])

      return vh_name

    except (RequestException, ValueError, Exception) as e:
      print(f"Error GET Security Events: {e}")
      return []

  def get_all_loadbalancers(self, verbose: bool = False) -> list:
    """
      Retrieves load balancers from a specified URL.

      Returns a list of load balancers based on certain conditions.

      Parameters:
      - verbose (bool, optional): A boolean value to enable/disable verbose mode. Defaults to False.

      Returns:
      - list[str]: A list of all load balancers obtained from the JSON response that matches lb_name.

      Raises:
      - requests.RequestException: If an error occurs while making the API request.
      - ValueError: If there is an issue with the provided parameters or response parsing.
      - Exception: If an unexpected error occurs.
    """

    # Get Load Balancers
    url_lb = f'https://{self.tenant}.console.ves.volterra.io/api/config/namespaces/{self.namespace}/http_loadbalancers'

    if verbose:
      print("Execute API calls to retrieve LBs")
    try:
      json_response = send_get_request(url_lb, self.api_key, verbose)

      if self.loadbalancer_name == 'all':
        return json_response['items']
      return [lb for lb in json_response['items'] if lb['name'] == self.loadbalancer_name]

    except (RequestException, ValueError, Exception) as e:
      print(f"Error GET Load Balancers: {e}")
      return []

  def get_security_events(self, lb_name: str, scroll_number: int, scroll_id: str | None = None, verbose: bool = False) -> list:
    """
    Retrieves security events for a specified load balancer.

    Parameters:
    - lb_name (str): The name of the load balancer.
    - scroll_number (int): The scroll number for pagination. Starts from 0.
    - scroll_id (str | None, optional): The scroll ID for fetching subsequent pages. Defaults to None.
    - verbose (bool, optional): A boolean value to enable/disable verbose mode. Defaults to False.

    Returns:
    - List[Dict[Any]]: A list of security events for the load balancer.

    Raises:
    - requests.RequestException: If an error occurs while making the API request.
    - ValueError: If there is an issue with the provided parameters or response parsing.
    - Exception: If an unexpected error occurs.
    """
    obj = []
    url = f'https://{self.tenant}.console.ves.volterra.io/api/data/namespaces/{self.namespace}/app_security/events'

    # Construct the URL with scroll ID if provided
    if scroll_id is not None:
      url = f'{url}/scroll?scroll_id={scroll_id}'

    # Construct the request body
    requestBody = {
        'namespace': self.namespace,
        'query': f'{{vh_name="{lb_name}", sec_event_type=~"waf_sec_event|bot_defense_sec_event|api_sec_event|svc_policy_sec_event"}}',
        "aggs": {},
        "scroll": True,
        "limit": self.limit_events if self.limit_events > 0 and self.limit_events < 500 else 500,
        "start_time": self.start_date,
        "end_time": self.to_date
    }

    try:
      # Make the API request
      data = send_post_request(url, requestBody, self.api_key,
                               verbose) if scroll_id is None else send_get_request(url, self.api_key, verbose)

      total_hits = int(data['total_hits'])
      if verbose:
        print(f"Total Events: {total_hits}")

      if total_hits == 0:
        print(f"No events found for {lb_name}")
        return []

      if total_hits > 500 and scroll_id is not None:
        if self.limit_events == 0 or (500 * scroll_number + 500) <= self.limit_events:
          events_gets_to = len(data['events']) + 500 * scroll_number
        else:
          events_gets_to = self.limit_events
      else:
        events_gets_to = len(data['events']) if scroll_id is None else len(data['events']) + 500 * scroll_number

      total_events = total_hits if self.limit_events == 0 or total_hits < self.limit_events else self.limit_events

      print(
        "Request #{}: Got {} events of {} ({:.1f}%) for {}".format(
          scroll_number + 1,
          get_string_number(events_gets_to),
          get_string_number(total_events),
          round(events_gets_to / total_events * 100, 1),
          lb_name
        ))

      # Append each event to the list
      for event in data['events']:
        obj.append(json.loads(event))

      # Recursive call if there is a scroll ID present
      scroll_id = data['scroll_id']
      if scroll_id != "":
        next_scroll_num = scroll_number + 1
        num_events_stored = len(obj) + (500 * scroll_number)
        if verbose:
          print(f'Events now: {len(obj)}')
          print(f"scroll number: {scroll_number}")
          print(f"Next scroll number: {next_scroll_num}")
          print(f'Next events: {next_scroll_num * 500}')
          print(f'Events stored: {num_events_stored}')
          print(f'Total events: {total_events}')
        if num_events_stored < total_events:
          obj_tmp = self.get_security_events(lb_name, next_scroll_num, scroll_id, verbose)
          obj.extend(obj_tmp)

    except (RequestException, ValueError, Exception) as e:
      # Print error message and return an empty list
      print(f'Error Exception for LB {lb_name}: {e}')
      return []

    if (self.limit_events > 0 and len(obj) > self.limit_events):
      if verbose:
        print(f"Limiting events to {self.limit_events}")
      obj = obj[:self.limit_events]
    return obj
