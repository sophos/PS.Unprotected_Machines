# Unprotected_Machines
This will compare all the machines in every Sophos Central MSP/EDB/Single Console and Active Directory. It will list all the machines not protected by Sophos Central and when those machines last spoke to a Domain Controller. Please follow the PDF guide

This script replaces the previous scripts Unprotected_Machines_EDB_MSP and Unprotected_Machines_Single_Tenant scripts into one script

v2025.1
Recoded how the last days are calculated. Milliseconds are now removed regardless of being present or not.

v2024.14
Swapped to the new version number format
Added a HTML report

v2.21
Fixed a unsupported hash type MD4 error

v2.19
Fixed an issue where the sub esate names may report incorrectly

v2.17
Fixed an issue where the script would fail when used with a Sophos Central Enterprise Dashboard or MSP

v2.16
The script will now check to see if machines have spoken to Active Directory and not to Sophos Central within 2 days of each other. This should find machines where they were rebuilt, are in Active Directory AND in Sophos Central, but have not had Sophos Central installed. If you have authenticated to Active Directory you should be able to speak to Sophos Central

v2.14
Fixed an issue when the script was run against a Sophos Central Enterprise Dashboard
