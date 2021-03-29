# microsoft-windows-server-2019-stig-baseline
InSpec profile to validate the secure configuration of Microsoft Windows Server 2019, against [DISA](https://iase.disa.mil/stigs/)'s Microsoft Windows Server 2019 Security Technical Implementation Guide (STIG) Version 1, Release 3.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
- Set to either the string "true" or "false"
sensitive_system: false

- List of temporary accounts on the domain
temp_accounts_domain: []

- List of temporary accounts on local system
temp_accounts_local: []

- List of emergency accounts on the domain
emergency_accounts_domain: []

- List of emergency accounts on the system
emergency_accounts_local: []

- List of authorized users in the local Administrators group for a domain controller
local_administrators_dc: []

- List of authorized users in the local Administrators group for a member server
local_administrators_member: []

- Local Administrator Account on Windows Server
local_administrator: ""

- List of authorized users in the Backup Operators Group
backup_operators: []

- List Application or Service Accounts domain
application_accounts_domain: []

- List Excluded Accounts domain
excluded_accounts_domain: []

- List Application Local Accounts
application_accounts_local: []

- List of authorized users in the local Administrators group
administrators: []

```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/microsoft-windows-server-2019-stig-baseline/archive/master.tar.gz --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-windows-server-2019-stig-baseline
inspec archive microsoft-windows-server-2019-stig-baseline
inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd microsoft-windows-server-2019-stig-baseline
git pull
cd ..
inspec archive microsoft-windows-server-2019-stig-baseline --overwrite
inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Jared Burns - [burnsjared0415](https://github.com/burnsjared0415)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Special Thanks

* Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/microsoft-windows-server-2019-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx