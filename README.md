# Microsoft Windows Server 2019 Security Technical Implementation Guide
This InSpec Profile was created to facilitate testing and auditing of `Microsoft Windows Server 2019`
infrastructure and applications when validating compliancy with Department of [Defense (DoD) STIG](https://iase.disa.mil/stigs/)
requirements

- Profile Version: 3.1.0
- STIG Date:  24 Jul 2024    
- STIG Version: Version 3 Release 1 (V3R1)


This profile was developed to reduce the time it takes to perform a security checks based upon the
STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA
Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO)
decision for the applicable technology.

The Microsoft Windows Server 2019 STIG Profile uses the [InSpec](https://github.com/inspec/inspec)
open-source compliance validation language to support automation of the required compliance, security
and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions
and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================
* [STIG Information](#stig-information)
* [Getting Started](#getting-started)
    * [Intended Usage](#intended-usage)
    * [Tailoring to Your Environment](#tailoring-to-your-environment)
    * [Testing the Profile Controls](#testing-the-profile-controls)
* [Running the Profile](#running-the-profile)
    * [Directly from Github](#directly-from-github) 
    * [Using a local Archive copy](#using-a-local-archive-copy)
    * [Different Run Options](#different-run-options)
* [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)

## STIG Information
The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set
of Security Technical Implementation Guides for applications, computer systems and networks
connected to the Department of Defense (DoD). These guidelines are the primary security standards
used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate
how security training should proceed and when security checks should occur. Organizations must
stay compliant with these guidelines or they risk having their access to the DoD terminated.

Requirements associated with the Microsoft Windows Server 2019 STIG are derived from the
[Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide)
and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST)
[Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53)
Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The Microsoft Windows Server 2019 STIG profile checks were developed to provide technical implementation
validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing
to enhance their security posture and can be tailored easily for use in your organization.

[top](#table-of-contents)
## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target remotely over __winrm__.

__For the best security of the runner, always install the _latest version_ of InSpec on the runner
    and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

[top](#table-of-contents)
### Intended Usage
1. The latest `released` version of the profile is intended for use in A&A testing, as well as
    providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
    Please use the `released` versions of the profile in these types of workflows. 

2. The `main` branch is a development branch that will become the next release of the profile.
    The `main` branch is intended for use in _developing and testing_ merge requests for the next
    release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

[top](#table-of-contents)
### Tailoring to Your Environment
The `inspec.yml` file contains metadata that describes the profile.

***[Update the `inspec.yml` file parameter `inputs` with a list of inputs appropriate
 for the profile and specific environment. Also update the inspec_version to the required version]***

Chef InSpec Resources:
- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/).
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/).
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/).

>[!NOTE]
> Inputs are variables that can be referenced by any control in the profile, and are defined
  and given a default value in the `inspec.yml` file.

Below is an example how the `inputs` are defined in the `inspec.yml`:
```
inputs:
  # Skip controls that take a long time to test 
  - name: disable_slow_controls
    description: Controls that are known to consistently have long run times can be disabled with this attribute
    type: Boolean
    value: false

  # List of configuration files for the specific system
  - name: logging_conf_files
    description: Configuration files for the logging service
    type: Array
    value:
      - <dir-path-1>/*.conf
      - <dir-path-2>/*.conf
```

For MS Windows 2019 the following minimal inputs should be provided:
```
# Set to either the string "true" or "false"
sensitive_system: false

# List of temporary accounts on the domain
temp_accounts_domain: []

# List of temporary accounts on local system
temp_accounts_local: []

# List of emergency accounts on the domain
emergency_accounts_domain: []

# List of emergency accounts on the system
emergency_accounts_local: []

# List of authorized users in the local Administrators group for a domain controller
local_administrators_dc: []

# List of authorized users in the local Administrators group for a member server
local_administrators_member: []

# Local Administrator Account on Windows Server
local_administrator: ""

# List of authorized users in the Backup Operators Group
backup_operators: []

# List Application or Service Accounts domain
application_accounts_domain: []

# List Excluded Accounts domain
excluded_accounts_domain: []

# List Application Local Accounts
application_accounts_local: []

# List of authorized users in the local Administrators group
administrators: []

```
[top](#table-of-contents)
### Testing the Profile Controls
The Gemfile provided contains all necessary ruby dependencies for checking the profile controls.
#### Requirements
All action are conducted using `ruby` (gemstone/programming language). Currently `inspec` 
commands have been tested with ruby version 3.1.2. A higher version of ruby is not guaranteed to
provide the expected results. Any modern distribution of Ruby comes with Bundler preinstalled by default.

Install ruby based on the OS being used, see [Installing Ruby](https://www.ruby-lang.org/en/documentation/installation/)

After installing `ruby` install the necessary dependencies by invoking the bundler command
(must be in the same directory where the Gemfile is located):
```
bundle install
```

#### Testing Commands
Ensure the controls are chef-style formatted:
```
  bundle exec cookstyle -a ./controls
```

Linting and validating controls:
```
  bundle exec rake inspec:check          # validate the inspec profile
  bundle exec rake lint                  # Run RuboCop
  bundle exec rake lint:autocorrect      # Autocorrect RuboCop offenses (only when it's safe)
  bundle exec rake lint:autocorrect_all  # Autocorrect RuboCop offenses (safe and unsafe)
  bundle exec rake pre_commit_checks     # pre-commit checks
```

Ensure the controls are ready to be committed into the repo:
```
  bundle exec rake pre_commit_checks
```


[top](#table-of-contents)
## Running the Profile
### Directly from Github
This options is best used when network connectivity is available and policies permit
access to the hosting repository.

```
# Using `ssh` transport
bundle exec inspec exec https://github.com/mitre/Microsoft Windows Server 2019 Security Technical Implementation Guide/archive/main.tar.gz --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec inspec exec https://github.com/mitre/Microsoft Windows Server 2019 Security Technical Implementation Guide/archive/master.tar.gz --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

[top](#table-of-contents)
### Using a local Archive copy
If your runner is not always expected to have direct access to the profile's hosted location,
use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below.
Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/Microsoft Windows Server 2019 Security Technical Implementation Guide.git
bundle exec inspec archive Microsoft Windows Server 2019 Security Technical Implementation Guide

# Using `ssh` transport
bundle exec inspec exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

For every successive run, follow these steps to always have the latest version of this profile baseline:

```
cd Microsoft Windows Server 2019 Security Technical Implementation Guide
git pull
cd ..
bundle exec inspec archive Microsoft Windows Server 2019 Security Technical Implementation Guide --overwrite

# Using `ssh` transport
bundle exec inspec exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec inspec exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

[top](#table-of-contents)
## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

[top](#table-of-contents)
## Using Heimdall for Viewing Test Results
The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.

Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)

Heimdall can **_export your results into a DISA Checklist (CKL) file_** for easily uploading into eMass using the `Heimdall Export` function.

Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.

Additionally both Heimdall applications can be deployed via docker, kurbernetes, or the installation packages.

[top](#table-of-contents)
## Authors
Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

MITRE Security Automation Framework Team https://saf.mitre.org

## NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
