import requests
import json
import os
from pandas import ExcelWriter, DataFrame

HEADERS = {'Authorization': 'APIToken', 'accept': 'application/json', 'Cache-Control': 'no-cache'}


def get_string_number(number: int) -> str:
  """
  Returns a formatted string representing the provided number.

  Parameters:
  - number (int): The number to be formatted.

  Returns:
  - str: The formatted string representing the number.

  The function formats the number in "1k", "1m", or "1b" mode using f-strings.
  If the number is greater than or equal to 1 billion, it is divided by 1 billion and the letter "b"
  is appended at the end to indicate billions.
  If the number is greater than or equal to 1 million but less than 1 billion, it is divided by 1 million
  and the letter "m" is appended at the end to indicate millions.
  If the number is greater than or equal to 1,000 but less than 1 million, it is divided by 1,000
  and the letter "k" is appended at the end to indicate thousands.
  If the number is less than 1,000, it is simply returned as a string.

  Examples:
  >>> get_string_number(1_500_000_000)
  '1.5b'
  >>> get_string_number(2_500_000)
  '2.5m'
  >>> get_string_number(3_500)
  '3.5k'
  >>> get_string_number(750)
  '750'
  """
  if number >= 1_000_000_000:
    formatted_number = f"{number/1_000_000_000:.1f}b"
  if number >= 1_000_000:
    formatted_number = f"{number/1_000_000:.1f}m"
  elif number >= 1_000:
    formatted_number = f"{number/1_000:.1f}k"
  else:
    formatted_number = str(number)

  return formatted_number


def saveToJSON(data: list, outputfile: str) -> bool:
  """
  Save a list to a JSON file.

  Parameters:
  - data: The list to be saved.
  - outputfile: The path to the JSON file.

  Returns:
  - bool: True if the list was successfully saved to the file, False otherwise.
  """
  try:
    file_path = os.path.join(os.getcwd(), outputfile)
    with open(file_path, 'w') as file:
      json.dump(data, file)
    return True
  except Exception as e:
    print(f"Error saving list to JSON file: {e}")
    return False


def saveToExcel(data: dict, outputfile: str) -> bool:
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
    writer = ExcelWriter(outputfile)

    for sheet, events in data.items():
      # Create a DataFrame for each sheet
      df = DataFrame(events)

      # Write the DataFrame to the sheet in the Excel file
      df.to_excel(writer, sheet_name=sheet, index=False)

    # Save the Excel file
    writer.close()

    return True

  except Exception as e:
    print(f"Error Pandas Exception: {e}")
    return False


def send_get_request(url: str, api_key: str, verbose: bool) -> dict:
  """
  Sends a GET request to the specified URL and returns the response data as a dictionary.

  Parameters:
  - url (str): The URL to send the GET request to.
  - api_key (str): The API key to use for authentication.
  - verbose (bool): Whether to print details about the API call.

  Returns:
  - dict: The response data parsed as a dictionary.

  Raises:
  - requests.RequestException: If the request encounters an error or a non-200 status code.
  - ValueError: If the response content cannot be parsed as JSON.
  - Exception: If an unexpected error occurs.

  This function sends a GET request to the provided URL using the requests library. It includes
  the HEADERS in the request for any necessary authentication or headers required by the API.
  If the VERBOSE flag is enabled, it prints details about the API call, including the request URL
  and headers.

  If the request is successful (returns a 200 status code), the response content is parsed as JSON
  and returned as a dictionary.

  If the request encounters an error or a non-200 status code, an error message is printed and
  an exception is raised. 
  """

  headers = HEADERS.copy()
  headers.update({'Authorization': f'APIToken {api_key}'})

  # Print API call details if verbose mode is enabled
  if verbose:
    print(f"Request URL: {url}")
    print(f"Request headers: {json.dumps(headers, indent=2)}")

  try:
    response_lb = requests.get(url, headers=headers)
    # Print response details if verbose mode is enabled
    if verbose:
      print(f"Response code: {response_lb.status_code}")
      print(f"Response content: {response_lb.text}")

    response_lb.raise_for_status()  # Raise an exception for non-200 status codes
    data = response_lb.json()  # Parse the JSON response

    return data

  except (requests.RequestException) as e:
    print(f"Error GET Request: {e}")
    raise


def send_post_request(url: str, requestBody: dict, api_key: str, verbose: bool) -> dict:
  """
  Sends a POST request to the specified XC URL with the provided request body and returns the response data as a dictionary.

  Parameters:
  - url (str): The URL to send the POST request to.
  - requestBody (dict): The request body as a dictionary.
  - api_key (str): The API key to use for authentication.
  - verbose (bool): Whether to print details about the API call.

  Returns:
  - dict: The response data parsed as a dictionary.

  Raises:
  - requests.RequestException: If the request encounters an error or a non-200 status code.
  - ValueError: If the response content cannot be parsed as JSON.
  - Exception: If an unexpected error occurs.

  This function sends a POST request to the provided URL using the requests library. It includes the HEADERS in the request for any necessary authentication or headers required by the API. The request body is sent as JSON using the json parameter of the requests.post() method.

  If the VERBOSE flag is enabled, it prints details about the API call, including the request URL, headers, and body.

  If the request is successful (returns a 200 status code), the response content is parsed as JSON and returned as a dictionary.

  If the request encounters an error or a non-200 status code, an error message is printed, and an exception is raised.

  Examples:
  >>> request_body = {'key1': 'value1', 'key2': 'value2'}
  >>> response_data = sendXCPostRequest("https://api.example.com/data", request_body)
  >>> print(response_data)
  {'response_key': 'response_value'}
  """

  headers = HEADERS.copy()
  headers.update({'Authorization': f'APIToken {api_key}'})
  headers.update({'Content-type': 'application/json'})

  # Print API call details if verbose mode is enabled
  if verbose:
    print(f"Request URL: {url}")
    print(f"Request headers: {json.dumps(headers, indent=2)}")
    print(f"Request body: {json.dumps(requestBody, indent=2)}")

  try:
    # Make the API request
    response = requests.post(url, headers=headers, json=requestBody)

    # Print response details if verbose mode is enabled
    if verbose:
      print(f"Response code: {response.status_code}")
      print(f"Response content: {response.text}")

    response.raise_for_status()  # Raise an exception for non-200 status codes
    data = response.json()

    return data

  except (requests.RequestException, ValueError, Exception) as e:
    print(f"Error POST Request: {e}")
    raise
