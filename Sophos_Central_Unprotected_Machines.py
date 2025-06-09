# Copyright 2019-2020 Sophos Limited
#
# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Sophos_Central_Unprotected_Machines.py
#
# Compares machines in Active Directory or Entra to machines in Sophos Central in all sub estates
# Machines NOT in Sophos Central will be exported to a csv and html report
# Suspicious machines are also added. These are machines that have not communicated to Sophos Central for more
# than three days after the last directory communication (could be a rebuild. Sophos Central was not re-installed)
#
# Thanks to Greg for helping with the beta testing of Entra support
# By: Michael Curtis
# Date: 29/5/2020
# Version v2025.30
# README: This script is an unsupported solution provided by
# Sophos Professional Services

# Class to add colours to the console output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


import requests
import csv
# Used for Entra authentication
from msal import ConfidentialClientApplication
import configparser
# Import datetime modules
from datetime import date
from datetime import datetime
from datetime import timedelta
from datetime import timezone
#Import OS to allow to check which OS the script is being run on
import os
# Import getpass for AD password input
import getpass
# From the LDAP module import required objects
# https://ldap3.readthedocs.io/searches.html
# from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM, SUBTREE
from ldap3 import Server, Connection, SIMPLE, SUBTREE
# This list will hold all the computers
list_of_machines_in_central = []
list_of_machines_in_central_with_days = []
# This list will hold all the computers not in Central
list_of_ad_computers_not_in_central = []
# This list will hold all the sub estates
sub_estate_list = []
# This list will hold all the computers in AD
list_of_computers_in_ad = []
# Put the machine name here to break on this machine
# debug_machine = 'MacBook Pro'
debug_machine = 'mc-nuc-winxi'
# Get todays date and time
today = date.today()
now = datetime.now()
time_stamp = str(now.strftime("%d%m%Y_%H-%M-%S"))

# Sophos Central Code

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    return headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_header= "X-Partner-ID"
    elif whoami["idType"] == "organization":
        organization_header = "X-Organization-ID"
    else:
        organization_header = "X-Tenant-ID"
    organization_id = whoami["id"]
    # The region_url is used if Sophos Central is a tenant
    region_url = whoami.get('apiHosts', {}).get("dataRegion", None)
    return organization_id, organization_header, organization_type, region_url

def get_all_sub_estates():
    # Add X-Organization-ID to the headers dictionary
    headers[organization_header] = organization_id
    # URL to get the list of tenants
    # Request all tenants
    request_sub_estates = requests.get(f"{'https://api.central.sophos.com/'}{organization_type}{'/v1/tenants?pageTotal=True'}", headers=headers)
    # Convert to JSON
    sub_estate_json = request_sub_estates.json()
    # Find the number of pages we will need to search to get all the sub estates
    total_pages = sub_estate_json["pages"]["total"]
    # Set the keys you want in the list
    sub_estate_keys = ('id', 'name', 'dataRegion', 'showAs')
    while (total_pages != 0):
    #Paged URL https://api.central.sophos.com/organization/v1/tenants?page=2 add total pages in a loop
        request_sub_estates = requests.get(f"{'https://api.central.sophos.com/'}{organization_type}{'/v1/tenants?page='}{total_pages}", headers=headers)
        sub_estate_json = request_sub_estates.json()
        #Add the tenants to the sub estate list
        for all_sub_estates in sub_estate_json["items"]:
            #Make a temporary Dictionary to be added to the sub estate list
            sub_estate_dictionary = {key:value for key, value in all_sub_estates.items() if key in sub_estate_keys}
            sub_estate_list.append(sub_estate_dictionary)
            print(f"Sub Estate - {sub_estate_dictionary['name']}. Sub Estate ID - {sub_estate_dictionary['id']}")
        total_pages -= 1
    # Remove X-Organization-ID from headers dictionary. We don't need this anymore
    del headers[organization_header]
    if show_sse_menu == 1:
        # Print list of sub estates
        for index, sub_estate_name in enumerate(sub_estate_list):
            print(index, "-", sub_estate_name)
        # Choose the sub estate you want to audit
        choice = input("Which sub estate do you want to audit? Enter the number or A for all: ")
        if choice.lower() != 'a':
            choice = int(choice)
            # Get the sub estate details from sub_estate_list
            temp = sub_estate_list[choice]
            # Clear the list. At this point it contains all the sub estates
            sub_estate_list.clear()
            # Add the sub estate you want to audit back into the empty sub_estate_list
            sub_estate_list.append(temp)
    print(f"Sub Estates Found: {(len(sub_estate_list))}")

def get_all_computers(sub_estate_token, url, sub_estate_name):
    # Get all Computers from sub estates
    print(f'Retrieving machines from - {sub_estate_name}')
    # Add pageSize to url
    url = (f"{url}{'/endpoints?pageSize=500'}")
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        #Sub estate to be searched
        sub_estate_id = sub_estate_token
        #Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = sub_estate_id
        #Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        #Convert to JSON
        computers_json = request_computers.json()
        #Set the keys you want in the list
        computer_keys = ('hostname',
                         'lastSeenAt')
        if request_computers.status_code == 403:
            print(f"No access to sub estate - {sub_estate_name}. Status Code - {request_computers.status_code}")
            break
        #Add the computers to the computers list
        for all_computers in computers_json["items"]:
            # Make a temporary Dictionary to be added to the sub estate list
            computer_dictionary = {key:value for key, value in all_computers.items() if key in computer_keys}
            # Old Code - central_computer_name = computer_dictionary['hostname']
            if 'lastSeenAt' in computer_dictionary.keys():
                computer_dictionary['Last_Seen'] = get_days_since_last_seen_sophos(computer_dictionary['lastSeenAt'])
            # Make Computer Name Upper Case for consistency
            # Check hostname exists
            if 'hostname' in computer_dictionary.keys():
                computer_dictionary['hostname'] = computer_dictionary['hostname'].upper()
                list_of_machines_in_central.append(computer_dictionary['hostname'])
                list_of_machines_in_central_with_days.append(computer_dictionary)
                # Need to make a new list here
                # Debug code. Uncomment the line below if you want to find the machine cause the error
                print(computer_dictionary['hostname'])
                # This line allows you to debug on a certain computer. Add computer name
                if 'CHE-LIBCT-01-13' == computer_dictionary['hostname']:
                    print('Add breakpoint here')
        # Check to see if you have more than 500 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = f"{url}{'&pageFromKey='}{next_page}"
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def get_days_since_last_seen_sophos(report_date):
    try:
        dt = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        dt = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S%z")

    # Remove microseconds and convert to date
    convert_last_seen_to_a_date = dt.replace(microsecond=0).date()

    # Today's date in UTC to match the timezone of the report date
    today = datetime.now(timezone.utc).date()

    days = (today - convert_last_seen_to_a_date).days
    return days


# Directory Code

# Entra Authentication
def get_entra_access_token(tenant_id, client_id, client_secret):
    # Get an access token using client credentials flow
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}"
    )

    # The scope needed for Device operations
    scopes = ["https://graph.microsoft.com/.default"]

    result = app.acquire_token_for_client(scopes=scopes)

    if "access_token" in result:
        return result["access_token"]
    else:
        error_description = result.get("error_description", "Unknown error")
        raise Exception(f"Failed to acquire token: {error_description}")

# Get Entra Devices
def get_all_entra_devices(entra_access_token):

    # Get all devices from Microsoft Graph API with pagination support
    # Including all join type related fields without interpretation

    # Contains the filtered devices
    entra_devices = []
    # NContains all the machines in Entra
    devices = []
    # Not used a present. Used as a comparison
    company_owned_devices = []
    # Request all relevant join type fields directly from the API
    next_link = "https://graph.microsoft.com/v1.0/devices?$select=id,displayName,approximateLastSignInDateTime,registrationDateTime,accountEnabled,deviceMetadata,managementType,enrollmentType,trustType,deviceOwnership,operatingSystem,operatingSystemVersion,joinType,mdmAppId,alternativeSecurityIds,physicalIds"

    headers = {
        "Authorization": f"Bearer {entra_access_token}",
        "Content-Type": "application/json"
    }

    while next_link:
        response = requests.get(next_link, headers=headers)

        if response.status_code == 200:
            data = response.json()
            devices.extend(data["value"])

            # Check if there are more pages
            next_link = data.get("@odata.nextLink", None)
        else:
            print(f"Error fetching devices: {response.status_code}")
            print(response.text)
            break
    # Filter out the machines that are NOT AzureDomainJoined or OnPremiseCoManaged
    for machines in devices:
        if machines['enrollmentType'] == "AzureDomainJoined" or machines['enrollmentType'] == "OnPremiseCoManaged":
            entra_devices.append(machines)
    for machines in devices:
        if machines['enrollmentType'] == "AzureDomainJoined" or machines['enrollmentType'] == "OnPremiseCoManaged":
            company_owned_devices.append(machines)
    return entra_devices

# Get AD computers
def get_ad_computers(search_domain, search_user, search_password, domain_controller, ldap_port):
    if ldap_port == 636:
        ldap_server = Server(domain_controller, port=ldap_port, use_ssl=True, get_info=SUBTREE)
        print('LDAPS is being used over port 636')
    else:
        ldap_server = Server(domain_controller, port=ldap_port, use_ssl=False, get_info=SUBTREE)
        print('LDAP is being used over port 389')
    #server_query = Connection(ldap_server, search_user, search_password, auto_bind=True, authentication=NTLM)
    server_query = Connection(ldap_server, search_user, search_password, authentication=SIMPLE,
                             auto_bind=True)
    computers_in_ad = server_query.extend.standard.paged_search(search_base=search_domain,
                                                          search_filter='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                                                          search_scope=SUBTREE,
                                                          # Sets the search attributes to the name and lastLogonTimestamp
                                                          attributes=['cn', 'lastLogonTimestamp',
                                                                      'operatingSystem', 'dn'],
                                                          paged_size=5,
                                                          generator=False)
    return (computers_in_ad)

# Compare machines from the directory chosen to Sophos Central
def compare_central_to_directory(computers_in_directory):
    print(f"{bcolors.OKGREEN}Comparing Sophos Central machines to Active Directory{bcolors.ENDC}")
    total_computers_in_ad = 0
    total_computers_in_central_and_ad = 0
    for entry in computers_in_directory:
        if 'attributes' in entry:
            # Sets computer attributes to the name, OS and lastLogonTimestamp
            computer_attributes = str(entry['attributes'])
            # Characters to be removed
            remove_characters_from_computer_attributes = ['[', '{', "'", "}", "]"," "]
            for remove_each_character in remove_characters_from_computer_attributes:
                computer_attributes = computer_attributes.replace(remove_each_character, '')
            # Split computer_attribtues at the , and then the :
            cn_only = computer_attributes.split(',')[0]
            cn_only = cn_only.split(':')[1]
            timestamp_only = computer_attributes.split(',')[2]
            timestamp_only = timestamp_only.split(':')[1]
            os_only = computer_attributes.split(',')[1]
            os_only = os_only.split(':')[1]
            # Checks to see if the os_only contains just numbers. If so, it is the timestamp and should changed
            if os_only.isdecimal():
                timestamp_only = os_only
                os_only ="Unknown"
            if os_only == "":
                os_only = 'Unknown'
            # Adds the split above to the dictionary_of_computers
            dictionary_of_ad_computers = {}
            dictionary_of_ad_computers['cn'] = cn_only
            dictionary_of_ad_computers['operatingSystem'] = os_only
            dictionary_of_ad_computers['lastLogonTimestamp'] = timestamp_only
            total_computers_in_ad += 1
            # This line allows you to debug on a certain computer. Add computer name
            if 'MC-NUC-DCIII' == cn_only:
                print('Add breakpoint here')
            #Get number of day since last logon. Check to see if lastLogonTimestamp is present
            if dictionary_of_ad_computers.get('lastLogonTimestamp') != "":
                dictionary_of_ad_computers['LastSeen'] = get_days_since_last_seen_ad_windows(dictionary_of_ad_computers.get('lastLogonTimestamp'))
            else:
                # Machines with no time stamp are set to 10000 days for better sorting later
                dictionary_of_ad_computers['LastSeen'] = 10000
            ad_computer_name = dictionary_of_ad_computers.get('cn')
            # Make Computer Name Upper Case for consistency
            ad_computer_name = ad_computer_name.upper()
            # Remove the computer name from the DN
            dn_only = entry['dn'].split(',',1)[-1]
            dictionary_of_ad_computers['dn'] = dn_only
            # Remove Microsoft time stamp from the dictionary
            del dictionary_of_ad_computers['lastLogonTimestamp']
            # If the computer is not in Central add it to list_of_ad_computers_not_in_central
            if ad_computer_name not in set_of_machines_in_central:
                # Add dictionary_of_computers to list_of_ad_computers
                # Changes the CN value to upper case to help the sort later
                dictionary_of_ad_computers['cn'] = ad_computer_name
                dictionary_of_ad_computers['Status'] = 'Unprotected'
                dictionary_of_ad_computers['LastCentralMessage'] = 'N/A'
                list_of_ad_computers_not_in_central.append(dictionary_of_ad_computers)
                print("a", end='')
            else:
                print("c", end='')
                total_computers_in_central_and_ad += 1
            # Add all AD machines to a list for later comparison
            list_of_computers_in_ad.append(dictionary_of_ad_computers)
    return total_computers_in_ad, total_computers_in_central_and_ad

# Convert the last login time stamp from Microsoft time to days
def get_days_since_last_seen_ad_windows(last_logon_date):
    # https://gist.github.com/caot/f57fbf419d6b37d53f6f4a525942cafc
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_logon_date_to_int = int(last_logon_date)
    if convert_last_logon_date_to_int == 0:
        return None
    epoch_start = datetime(year=1601, month=1, day=1)
    seconds_since_epoch = convert_last_logon_date_to_int / 10 ** 7
    converted_timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)
    # Remove the time from convert_last_seen_to_a_date
    converted_timestamp = datetime.date(converted_timestamp)
    days = (today - converted_timestamp).days
    return days

def get_days_since_last_seen_entra(lastSignInTime):
    date_formats_to_try = [
        "%Y-%m-%d %I:%M %p",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d",
        "%d/%m/%Y",
    ]

    # reported_date = filtered_row['approximateLastSignInDateTime']
    parsed_date = None
    for date_format in date_formats_to_try:
        try:
            parsed_date = datetime.strptime(lastSignInTime.strip(), date_format)
            break
        except ValueError:
            continue
    if parsed_date:
        days_since_last_seen_in_entra = (datetime.now() - parsed_date).days
    else:
        days_since_last_seen_in_entra = 10000  # Default if date can't be parsed
    # filtered_row['days_since_last_signin'] = days_since
    return days_since_last_seen_in_entra

# Compare last Sophos Central message days to directory days. Mark suspicious if great than 3 days
def compare_last_ad_logon_to_last_central_time(list_of_computers_in_ad,list_of_machines_in_central_with_days):
    dictionary_of_suspicious_computers = {}
    for ad_hostname in list_of_computers_in_ad:
        a_hostname = ad_hostname['cn']
        ad_days = ad_hostname['LastSeen']
        for central_hostname in list_of_machines_in_central_with_days:
            c_hostname = central_hostname['hostname']
            c_days = central_hostname['Last_Seen']
            if a_hostname == c_hostname:
                # Puts in a buffer of three days between AD and Central before the machine becomes suspicious
                if ad_days < c_days -2:
                    dictionary_of_suspicious_computers['Status'] = 'Suspicious'
                    dictionary_of_suspicious_computers['LastCentralMessage'] = c_days
                    dictionary_of_suspicious_computers.update(ad_hostname)
                    list_of_ad_computers_not_in_central.append(dictionary_of_suspicious_computers.copy())
                if a_hostname == 'MC-NUC-SGNI':
                    print()

# Writes the CSV report
def print_report(cloud_directory):
    full_report_path = f"{report_file_path}{report_name}{time_stamp}{'.csv'}"
    # Customise the column headers
    report_column_names = ['Status',
                  'Hostname Machine',
                  'Operating System',
                  'Last AD Login (Days)',
                  'DN',
                  'Last Central Message (Days)',
                           ]
    # Customise the column order
    report_column_order = ['Status',
                           'cn',
                           'operatingSystem',
                           'LastSeen',
                           'dn',
                           'LastCentralMessage',
                           ]
    # Add serial number to the report. Not used at present
    # Added DeviceID to the report
    # The above are only used with Entra
    if cloud_directory == 1:
        # report_column_names.append('Serial Number')
        # report_column_order.append('serial Number')
        report_column_names.append('Device ID')
        report_column_order.append('deviceID')
        report_column_names.append('Management Type')
        report_column_order.append('managementType')
    with open(full_report_path, 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Percentage Protected', unprotected_percentage])
        writer.writerow(report_column_names)
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, report_column_order)
            dict_writer.writerows(list_of_ad_computers_not_in_central)

# Writes the HTML report
def print_html_report(cloud_directory):
    # Custom column headers and order
    headers = ['Status', 'Hostname Machine', 'Operating System', 'Last AD Login (Days)', 'DN', 'Last Central Message (Days)']
    column_order = ['Status', 'cn', 'operatingSystem', 'LastSeen', 'dn', 'LastCentralMessage']
    numeric_fields = ['LastSeen', 'LastCentralMessage']  # Columns that require numeric filtering
    if cloud_directory == 1:
        headers.append('Device ID')
        column_order.append('deviceID')
        headers.append('Management Type')
        column_order.append('managementType')
    # Start HTML content with table styling and filter script
    html_content = '''
    <html>
    <head>
        <title>AD Computers Report</title>
        <style>
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #007bff; color: white; }  /* Updated header color */
            input { margin: 5px 0; width: 100%; }
        </style>
        <script>
            function applyFilter(cellValue, filterValue) {
                let operator = '';
                let value;

                if (filterValue.includes('>=')) { operator = '>='; value = parseFloat(filterValue.split('>=')[1].trim()); }
                else if (filterValue.includes('>')) { operator = '>'; value = parseFloat(filterValue.split('>')[1].trim()); }
                else if (filterValue.includes('<=')) { operator = '<='; value = parseFloat(filterValue.split('<=')[1].trim()); }
                else if (filterValue.includes('<')) { operator = '<'; value = parseFloat(filterValue.split('<')[1].trim()); }
                else if (filterValue.includes('=')) { operator = '='; value = parseFloat(filterValue.split('=')[1].trim()); }
                else { return cellValue.includes(filterValue); }

                return evaluateComparison(cellValue, operator, value);
            }

            function evaluateComparison(cellValue, operator, value) {
                const numericValue = parseFloat(cellValue);
                switch (operator) {
                    case '>=': return numericValue >= value;
                    case '>': return numericValue > value;
                    case '<=': return numericValue <= value;
                    case '<': return numericValue < value;
                    case '=': return numericValue === value;
                    default: return false;
                }
            }

            function filterTable() {
                const filters = document.querySelectorAll('input');
                const table = document.getElementById('dataTable');
                const rows = table.getElementsByTagName('tr');

                for (let i = 2; i < rows.length; i++) {  // Start filtering from the 3rd row
                    let shouldDisplay = true;
                    const cells = rows[i].getElementsByTagName('td');

                    for (let j = 0; j < filters.length; j++) {
                        const filterValue = filters[j].value.toLowerCase();
                        const cellValue = cells[j].textContent.toLowerCase();

                        if (filterValue) {
                            if (filters[j].classList.contains('numeric')) {  // Numeric field check
                                if (!applyFilter(cellValue, filterValue)) {
                                    shouldDisplay = false;
                                    break;
                                }
                            } else {
                                if (!cellValue.includes(filterValue)) {
                                    shouldDisplay = false;
                                    break;
                                }
                            }
                        }
                    }
                    rows[i].style.display = shouldDisplay ? '' : 'none';
                }
            }
        </script>
    </head>
    <body>
        <h2>Machines at risk of not having Sophos Central installed</h2>
        <table id="dataTable">
            <tr>'''

    # Create table headers
    for header in headers:
        html_content += f'<th>{header}</th>'
    html_content += '</tr>'

    # Create filter inputs row
    html_content += '<tr>'
    for col in column_order:
        if col in numeric_fields:  # Numeric field
            html_content += f'<td><input type="text" onkeyup="filterTable()" placeholder="Filter by {col} (use >, <, >=, <=, =)..." class="numeric"></td>'
        else:
            html_content += f'<td><input type="text" onkeyup="filterTable()" placeholder="Filter by {col}..."></td>'
    html_content += '</tr>'

    # Populate table rows with data
    for computer in list_of_ad_computers_not_in_central:
        html_content += '<tr>'
        for col in column_order:
            value = computer.get(col, 'N/A')  # Default to 'N/A' if the key is missing
            html_content += f'<td>{value}</td>'
        html_content += '</tr>'

    # Close HTML tags
    html_content += '''
        </table>
    </body>
    </html>'''

    # Write HTML content to file
    full_report_path = f"{report_file_path}{report_name}{time_stamp}.html"
    with open(full_report_path, 'w') as file:
        file.write(html_content)

    print(f'HTML report created at: {full_report_path}')

def compare_central_to_entra(computers_in_entra):
    print(f"{bcolors.OKGREEN}Comparing Sophos Central machines to Entra{bcolors.ENDC}")
    total_computers_in_ad = 0
    total_computers_in_central_and_directory = 0
    for computer in computers_in_entra:
            dictionary_of_ad_computers = {}
            dictionary_of_ad_computers['cn'] = computer['displayName']
            dictionary_of_ad_computers['operatingSystem'] = computer['operatingSystem']
            # dictionary_of_ad_computers['lastLogonTimestamp'] = timestamp_only
            total_computers_in_ad += 1
            # This line allows you to debug on a certain computer. Add computer name
            if debug_machine == computer['displayName']:
                print('Add breakpoint here')
            # Get number of days since last logon. Check if 'approximateLastSignInDateTime' is present and valid
            last_seen_str = computer.get('approximateLastSignInDateTime')
            if last_seen_str:
                try:
                    dt = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
                    dictionary_of_ad_computers['LastSeen'] = (datetime.now(dt.tzinfo) - dt).days
                except ValueError:
                    dictionary_of_ad_computers['LastSeen'] = 10000
            else:
                dictionary_of_ad_computers['LastSeen'] = 10000
            ad_computer_name = dictionary_of_ad_computers.get('cn')
            # Make Computer Name Upper Case for consistency
            ad_computer_name = ad_computer_name.upper()
            # dictionary_of_ad_computers['dn'] = computer['trustType']
            dictionary_of_ad_computers['dn'] = computer['enrollmentType']
            dictionary_of_ad_computers['managementType'] = computer['managementType']
            # If the computer is not in Central add it to list_of_ad_computers_not_in_central
            if ad_computer_name not in set_of_machines_in_central:
                # Add dictionary_of_computers to list_of_ad_computers
                # Changes the CN value to upper case to help the sort later
                dictionary_of_ad_computers['cn'] = ad_computer_name
                dictionary_of_ad_computers['Status'] = 'Unprotected'
                dictionary_of_ad_computers['LastCentralMessage'] = 'N/A'
                dictionary_of_ad_computers['deviceID'] = computer['id']
                # dictionary_of_ad_computers['Serial Number'] = computer['serialNumber']
                list_of_ad_computers_not_in_central.append(dictionary_of_ad_computers)
                print("a", end='')
            else:
                print("c", end='')
                # Add the deviceID is case it is needed later
                dictionary_of_ad_computers['deviceID'] = computer['id']
                total_computers_in_central_and_directory += 1
            # Add all AD machines to a list for later comparison
            list_of_computers_in_ad.append(dictionary_of_ad_computers)
    return total_computers_in_ad, total_computers_in_central_and_directory

# Read the config file
def read_config():
    config = configparser.ConfigParser()
    config.read('Sophos_Central_Unprotected_Machines.config')
    config.sections()
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    if client_secret == '':
        client_secret = getpass.getpass(prompt='Enter Client Secret: ', stream=None)
    report_name = config['REPORT']['ReportName']
    report_file_path = config['REPORT']['ReportFilePath']
    search_domain = config['DOMAIN']['SearchDomain']
    search_user = config['DOMAIN']['SearchUser']
    domain_controller = config['DOMAIN']['DomainController']
    ldap_port = config['DOMAIN']['LDAPPort']
    ldap_port = int(ldap_port)
    entra_client_id = config['Entra']['Entra_ClientID']
    entra_tenant_id = config['Entra']['Entra_TenantID']
    entra_client_secret = config['Entra']['Entra_ClientSecret']
    if entra_client_secret == '':
        entra_client_secret = getpass.getpass(prompt='Enter Entra Client Secret: ', stream=None)
    show_sse_menu = config.getint('EXTRA_FIELDS','Show_sse_menu')
    list_all_machines = config.getint('EXTRA_FIELDS','List_all_machines')
    #Checks if the last character of the file path contanins a \ or / if not add one
    if report_file_path[-1].isalpha():
         if os.name != "posix":
             report_file_path = report_file_path + "\\"
         else:
             report_file_path = report_file_path + "/"
    return(client_id, client_secret, report_name, report_file_path, search_domain, search_user, domain_controller, ldap_port,entra_client_id, entra_tenant_id, entra_client_secret, show_sse_menu,list_all_machines)

def menu():
    print(f"{bcolors.OKGREEN}Sophos Central Unprotected Machines{bcolors.ENDC}\n\n"
          "1) On Premise (Domain Controller)\n"
          "2) Entra\n"
          "Q) Quit")
    choice = input(f"{bcolors.OKBLUE}Please select option:{bcolors.ENDC}")
    if choice == '1':
        cloud_directory = 0
        return cloud_directory
    if choice == '2':
        cloud_directory = 1
        return cloud_directory
    if choice == 'Q' or 'q':
        quit()
    else:
        menu()

client_id, client_secret, report_name, report_file_path, search_domain, search_user, domain_controller, ldap_port, entra_client_id, entra_tenant_id, entra_client_secret, show_sse_menu, list_all_machines = read_config()
token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers = get_bearer_token(client_id, client_secret, token_url)
organization_id, organization_header, organization_type, region_url = get_whoami()
entra_access_token = get_entra_access_token(entra_tenant_id, entra_client_id, entra_client_secret)

cloud_directory = menu()

# Get machines from Sophos Central
if organization_type != "tenant":
    print(f"{bcolors.OKCYAN}Sophos Central is a {organization_type}{bcolors.ENDC}")
    get_all_sub_estates()
    for sub_etates_in_list in range(len(sub_estate_list)):
        sub_estate = sub_estate_list[sub_etates_in_list]
        get_all_computers(sub_estate['id'],
                          f"{'https://api-'}{sub_estate['dataRegion']}{'.central.sophos.com/endpoint/v1'}",
                          sub_estate['showAs'])
else:
    print(f"{bcolors.OKCYAN}Sophos Central is a {organization_type}{bcolors.ENDC}")
    # Removes sub estate name from report if the console is a single tenant
    get_all_computers(organization_id,
                      f"{region_url}{'/endpoint/v1'}",
                      organization_type)

set_of_machines_in_central = set(list_of_machines_in_central)
number_of_machines_in_central = len(list_of_machines_in_central)

if cloud_directory == 0:
    print(f"{bcolors.OKCYAN}Using On Premise Directory{bcolors.ENDC}")
    search_user_password = getpass.getpass(prompt='LDAP Password: ', stream=None)
    # get list of ad_computers
    machines_in_directory = get_ad_computers(search_domain,search_user,search_user_password,domain_controller, ldap_port)
    # Compare AD computers to Central machines
    number_of_machines_in_ad, number_of_machines_in_central_and_ad = compare_central_to_directory(machines_in_directory)
    # Compare last AD logon to Central last seen time to see if any rebuilds have missing installs
    compare_last_ad_logon_to_last_central_time(list_of_computers_in_ad,list_of_machines_in_central_with_days)
else:
    print(f"{bcolors.OKCYAN}Using Entra Directory. Please wait while the data is downloaded.{bcolors.ENDC}")
    entra_devices = get_all_entra_devices(entra_access_token)
    number_of_machines_in_ad, number_of_machines_in_central_and_ad = compare_central_to_entra(entra_devices)
    compare_last_ad_logon_to_last_central_time(list_of_computers_in_ad,list_of_machines_in_central_with_days)
    print()

unprotected_percentage = int((number_of_machines_in_central_and_ad / number_of_machines_in_ad) *100)

print('\n' + 'Number of machines not protected/suspicious:', len(list_of_ad_computers_not_in_central))
print('Number of machines in Directory', number_of_machines_in_ad)
print('Number of machines in Central', number_of_machines_in_central)
print('Number of machines in Central and Directory', number_of_machines_in_central_and_ad)
print('Percentage Protected is', unprotected_percentage,'%')
# Sort the machines in order. Recently online first
list_of_ad_computers_not_in_central.sort(key=lambda item: item.get("LastSeen"))
print_report(cloud_directory)
print_html_report(cloud_directory)
