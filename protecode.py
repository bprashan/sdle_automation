import requests
import time
import argparse
import os

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#os.environ['HTTP_PROXY']  = "http://proxy-chain.intel.com:911"
#os.environ['HTTPS_PROXY'] = "http://proxy-chain.intel.com:912"

# PROTECODE URL
PROTECODE_URL = "https://bdba001.icloud.intel.com"

# HEADERS
GROUP_ID_NUMBER = "54"

# CREDENTIALS
USERNAME = "sys_mpci"

# Analysis STATUSES
BUSY = "B"
READY = "R"
FAILED = "F"

WAITING_TIME = 60


def upload_application(application_file_name, password):
  """
    Uploads file to Protecode.
    :param application_file_name: The name of file that should be uploaded.
    :param password: Password to Protecode for sys_epidbld user.
    :return: product_id: Returns the identifier of the uploaded file.
    :raise: throws an exception if something's wrong.
    """
  try:
    with open(application_file_name, 'rb') as file:
      print(application_file_name)
      print(password)
      print(PROTECODE_URL)
      print(USERNAME)
      print("Uploading application {} to Protecode ...".format(
          application_file_name))
      response = requests.put(
          PROTECODE_URL + "/api/upload/{}".format(application_file_name),
          data=file,
          headers={"Group": GROUP_ID_NUMBER},
          auth=(USERNAME, password),
          verify=False).json()
      print(response)
  except Exception as e:
    raise RuntimeError(
        "Problem with uploading application: {}, received status {}".format(
            application_file_name,
            response.status_code))
  return response["results"]["product_id"]


def get_analysis_status(product_id, password):
  """
    Analysis status for file in Protecode.
    :param product_id: The identifier of the uploaded file.
    :param password: Password to Protecode for sys_epidbld user.
    :return: status_code: Returns one of the status code from Protecode B = Busy | R = Ready | F = Failed
    :raise: throws an exception if something's wrong.
    """
  try:
    response = requests.get(
        PROTECODE_URL + "/api/product/{}".format(product_id),
        auth=(USERNAME, password),
        verify=False).json()
    return response["results"]["status"]
  except Exception as e:
    raise RuntimeError(
        "Problem with retrieving status for product_id {}".format(product_id))


def download_report(product_id, destination_file_name, format, password):
  """
    Downloads specified report from Protecode.
    :param product_id: The identifier of the uploaded file.
    :param destination_file_name: The name of the saved report.
    :param format: The format of a report - more information https://protecode.devtools.intel.com/help/api/#results
    :param password: Password to Protecode for sys_epidbld user.
    :return: None
    :raise: throws an exception if something's wrong.
    """
  try:
    response = requests.get(PROTECODE_URL + "/api/product/{}/{}"
                            .format(product_id, format),
                            auth=(USERNAME, password),
                            verify=False)

    if response.status_code != 200:
      raise RuntimeError(
          "Problem with downloading a report {} for product_id {}, received status: {}"
            .format(format,
                    product_id,
                    response.status_code))
    open(destination_file_name, "wb").write(response.content)
  except Exception as e:
    raise RuntimeError(
        "Something unexpected happened while downloading a report {} for product_id {}"
          .format(format,
                  product_id))


def perform_protecode_scan(application_file_name, password):
  """
    The main function responsible for uploading application and downloading reports
    :param application_file_name: The name of file that should be uploaded.
    :param password: Password to Protecode for sys_epidbld user.
    :raise: throws an exception if something's wrong.
    """
  product_id = upload_application(application_file_name, password)
  while True:
    print("Getting analysis report for {}.".format(application_file_name))
    status = get_analysis_status(product_id, password)
    if status == FAILED:
      raise RuntimeError("Problem with scanning application {} in Protecode."
                         .format(application_file_name))
    if status == BUSY:
      print("Reports are not ready for {} - waiting {} seconds.".format(
          application_file_name, WAITING_TIME))
      time.sleep(WAITING_TIME)
      continue
    break

  download_pdf_report(product_id, 'test_bdba_scan_report' + ".pdf", password)
  download_csv_vulnerabilities_report(product_id,
                                      'test_bdba_scan_report' + ".csv", password)


def download_pdf_report(product_id, file_name, password):
  """
    Wrapper for downloading pdf report.
    :param product_id: The identifier of the uploaded file.
    :param file_name: The name of the saved report.
    :param password: Password to Protecode for sys_epidbld user.
    """
  print("Downloading pdf report for {}.".format(file_name))
  download_report(product_id, file_name, "pdf-report", password)


def download_csv_vulnerabilities_report(product_id, file_name, password):
  """
   Wrapper for downloading csv vulnerabilities report.
   :param product_id: The identifier of the uploaded file.
   :param file_name: The name of the saved report.
   :param password: Password to Protecode for sys_mpci user.
   """
  print("Downloading csv vulnerabilities report for {}.".format(file_name))
  download_report(product_id, file_name, "csv-vulns", password)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Scan application in Protecode.')
  parser.add_argument('--application_file_name',
                      help='The name of file that should be uploaded.',
                      required='YES', metavar='')
  parser.add_argument('--password',
                      help='Password to Protecode for sys_mpci user.',
                      required='YES', metavar='')

  args = parser.parse_args()
  start_time = time.time()
  perform_protecode_scan(args.application_file_name, args.password)
  elapsed_time = time.time() - start_time
  print(elapsed_time)