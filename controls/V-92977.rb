# encoding: UTF-8

control "V-92977" do
  title "Windows Server 2019 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours."
  desc  "Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
    Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.
    To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc  "rationale", ""
  desc  'check', "Determine if emergency administrator accounts are used and identify any that exist. If none exist, this is NA.
    If emergency administrator accounts cannot be configured with an expiration date due to an ongoing crisis, the accounts must be disabled or removed when the crisis is resolved.
    If emergency administrator accounts have not been configured with an expiration date or have not been disabled or removed following the resolution of a crisis, this is a finding.

    Domain Controllers:
    Open \"PowerShell\".
    Enter \"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate\".
    If \"AccountExpirationDate\" has been defined and is not within 72 hours for an emergency administrator account, this is a finding.

    Member servers and standalone systems:
    Open \"Command Prompt\".
    Run \"Net user [username]\", where [username] is the name of the emergency account.
    If \"Account expires\" has been defined and is not within 72 hours for an emergency administrator account, this is a finding."
  desc  'fix', "Remove emergency administrator accounts after a crisis has been resolved or configure the accounts to automatically expire within 72 hours.
    Domain accounts can be configured with an account expiration date, under \"Account\" properties.
    Local accounts can be configured to expire with the command \"Net user [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary user account."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000123-GPOS-00064'
  tag 'gid': 'V-92977'
  tag 'rid': 'SV-103065r1_rule'
  tag 'stig_id': 'WN19-00-000310'
  tag 'fix_id': 'F-99223r1_fix'
  tag 'cci': ["CCI-001682"]
  tag 'nist': ["AC-2 (2)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  
  if domain_role == '4' || domain_role == '5'
    emergency_accounts_list = input('emergency_accounts_domain')
    if emergency_accounts_list == [nil]
      impact 0.0
      describe 'There are no Emergency Account listed for this Control' do
        skip 'This becomes a manual check if the input emergency_accounts_domain is not assigned a value'
      end
    else
      emergency_accounts = []
      emergency_accounts_list.each do |emergency_account|
        emergency_accounts << json({ command: "Get-ADUser -Identity #{emergency_account} -Properties WhenCreated, AccountExpirationDate | Select-Object -Property SamAccountName, @{Name='WhenCreated';Expression={$_.WhenCreated.ToString('yyyy-MM-dd')}}, @{Name='AccountExpirationDate';Expression={$_.AccountExpirationDate.ToString('yyyy-MM-dd')}}| ConvertTo-Json"}).params
      end
      emergency_accounts.each do |emergency_account|
        account_name = emergency_account.fetch("SamAccountName")
        creation_date = Date.parse(emergency_account.fetch("WhenCreated"))
        expiration_date = Date.parse(emergency_account.fetch("AccountExpirationDate"))
        date_difference = expiration_date.mjd - creation_date.mjd
        describe "Account expiration set for #{account_name}" do
          subject { date_difference }
          it { should cmp <= input('emergency_account_period')}
        end
      end
    end

  else
    emergency_accounts_list = input('emergency_accounts_local')
    if emergency_accounts_list == [nil]
      impact 0.0
      describe 'There are no Emergency Account listed for this Control' do
        skip 'This is not applicable as there are no Emergency Account listed for this Control'
      end
    else
      emergency_accounts = []
      emergency_accounts_list.each do |emergency_account|
        emergency_accounts << json({ command: "Get-LocalUser -Name #{emergency_account} | Select-Object -Property Name, @{Name='PasswordLastSet';Expression={$_.PasswordLastSet.ToString('yyyy-MM-dd')}}, @{Name='AccountExpires';Expression={$_.AccountExpires.ToString('yyyy-MM-dd')}} | ConvertTo-Json"}).params
      end
      emergency_accounts.each do |emergency_account|
        user_name = emergency_account.fetch("Name")
        password_date = Date.parse(emergency_account.fetch("PasswordLastSet"))
        expiration_date = Date.parse(emergency_account.fetch("AccountExpires"))
        date_difference = expiration_date.mjd - password_date.mjd
        describe "Account expiration set for #{user_name}" do
          subject { date_difference }
          it { should cmp <= input('emergency_account_period')}
        end
      end
    end
  end
end