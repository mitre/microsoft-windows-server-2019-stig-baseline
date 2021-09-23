# encoding: UTF-8

 control 'V-92975' do
    title 'Windows Server 2019 must automatically remove or disable temporary user accounts after 72 hours.'
    desc  "If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

    Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.
    If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.
    To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
    desc  'rationale', ''
    desc  'check', "Review temporary user accounts for expiration dates.
    Determine if temporary user accounts are used and identify any that exist. If none exist, this is NA.

    Domain Controllers:
    Open \"PowerShell\".
    Enter \"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate\".
    If \"AccountExpirationDate\" has not been defined within 72 hours for any temporary user account, this is a finding.

    Member servers and standalone systems:
    Open \"Command Prompt\".
    Run \"Net user [username]\", where [username] is the name of the temporary user account.
    If \"Account expires\" has not been defined within 72 hours for any temporary user account, this is a finding."
    desc 'fix', "Configure temporary user accounts to automatically expire within 72 hours.
    Domain accounts can be configured with an account expiration date, under \"Account\" properties.
    Local accounts can be configured to expire with the command \"Net user [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary user account.
    Delete any temporary user accounts that are no longer necessary."
    impact 0.5
    tag 'severity': nil
    tag 'gtitle': 'SRG-OS-000002-GPOS-00002'
    tag 'gid': 'V-92975'
    tag 'rid': 'SV-103063r1_rule'
    tag 'stig_id': 'WN19-00-000300'
    tag 'fix_id': 'F-99221r1_fix'
    tag 'cci': ['CCI-000016']
    tag 'nist': ['AC-2 (2)', 'Rev_4']

    domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

    if domain_role == '4' || domain_role == '5'
      expiring_accounts = []
      temporary_accounts = input('temp_accounts_domain')
      unless temporary_accounts == [nil]
        temporary_accounts.each do |temporary_account|
          expiring_accounts << json({ command: "Get-ADUser -Identity #{temporary_account} -Properties WhenCreated, AccountExpirationDate | Select-Object -Property SamAccountName, @{Name='WhenCreated';Expression={$_.WhenCreated.ToString('yyyy-MM-dd')}}, @{Name='AccountExpirationDate';Expression={$_.AccountExpirationDate.ToString('yyyy-MM-dd')}}| ConvertTo-Json" }).params
        end
      end
      ad_accounts = json({ command: "Get-ADUser -Filter 'Enabled -eq $true' -Properties WhenCreated, AccountExpirationDate | Select-Object -Property SamAccountName, @{Name='WhenCreated';Expression={$_.WhenCreated.ToString('yyyy-MM-dd')}}, @{Name='AccountExpirationDate';Expression={$_.AccountExpirationDate.ToString('yyyy-MM-dd')}}| ConvertTo-Json" }).params
      if ad_accounts.empty?
        impact 0.0
        describe 'This control is not applicable as no user accounts were found' do
          skip 'This control is not applicable as no user accounts were found'
        end
      else
        case ad_accounts
        when Hash # One user account
          if ad_accounts.fetch('AccountExpirationDate').nil?
            impact 0.0
            describe 'This control is not applicable as no expiring user accounts were found' do
              skip 'This control is not applicable as no expiring user accounts were found'
            end
          else
            expiring_accounts << ad_accounts unless expiring_accounts.any? { |h| h['SamAccountName'] == ad_accounts.fetch('SamAccountName') }
          end
        when Array # Multiple user accounts
          ad_accounts.each do |ad_account|
            next if ad_account.fetch('AccountExpirationDate').nil?
            expiring_accounts << ad_account unless expiring_accounts.any? { |h| h['SamAccountName'] == ad_account.fetch('SamAccountName') }
          end
        end
      end
      if expiring_accounts.empty?
        impact 0.0
        describe 'This control is not applicable as no expiring user accounts were found' do
          skip 'This control is not applicable as no expiring user accounts were found'
        end
      else
        expiring_accounts.each do |expiring_account|
          account_name = expiring_account.fetch('SamAccountName')
          creation_date = Date.parse(expiring_account.fetch('WhenCreated'))
          expiration_date = Date.parse(expiring_account.fetch('AccountExpirationDate'))
          date_difference = expiration_date.mjd - creation_date.mjd
          describe "Account expiration set for #{account_name}" do
            subject { date_difference }
            it { should cmp <= input('temporary_account_period') }
          end
        end
      end

    else
      expiring_users = []
      temporary_accounts = input('temp_accounts_local')
      unless temporary_accounts == [nil]
        temporary_accounts.each do |temporary_account|
          expiring_users << json({ command: "Get-LocalUser -Name #{temporary_account} | Select-Object -Property Name, @{Name='PasswordLastSet';Expression={$_.PasswordLastSet.ToString('yyyy-MM-dd')}}, @{Name='AccountExpires';Expression={$_.AccountExpires.ToString('yyyy-MM-dd')}} | ConvertTo-Json" }).params
        end
      end
      local_users = json({ command: "Get-LocalUser * | Select-Object -Property Name, @{Name='PasswordLastSet';Expression={$_.PasswordLastSet.ToString('yyyy-MM-dd')}}, @{Name='AccountExpires';Expression={$_.AccountExpires.ToString('yyyy-MM-dd')}} | ConvertTo-Json" }).params
      if local_users.empty?
        impact 0.0
        describe 'This control is not applicable as no user accounts were found' do
          skip 'This control is not applicable as no user accounts were found'
        end
      else
        case local_users
        when Hash # One user account
          if local_users.fetch('AccountExpires').nil? || local_user.fetch('PasswordLastSet').nil?
            impact 0.0
            describe 'This control is not applicable as no expiring user accounts with password last set date were found' do
              skip 'This control is not applicable as no expiring user accounts password last set date were found'
            end
          else
            expiring_users << local_users unless expiring_users.any? { |h| h['Name'] == local_users.fetch('Name') }
          end
        when Array # Multiple user accounts
          local_users.each do |local_user|
            next if local_user.fetch('AccountExpires').nil? || local_user.fetch('PasswordLastSet').nil?
            expiring_users << local_user unless expiring_users.any? { |h| h['Name'] == local_user.fetch('Name') }
          end
        end
      end
      if expiring_users.empty?
        impact 0.0
        describe 'This control is not applicable as no expiring user accounts with password last set date were found' do
          skip 'This control is not applicable as no expiring user accounts with password last set date were found'
        end
      else
        expiring_users.each do |expiring_account|
          user_name = expiring_account.fetch('Name')
          password_date = Date.parse(expiring_account.fetch('PasswordLastSet'))
          expiration_date = Date.parse(expiring_account.fetch('AccountExpires'))
          date_difference = expiration_date.mjd - password_date.mjd
          describe "Account expiration set for #{user_name}" do
            subject { date_difference }
            it { should cmp <= input('temporary_account_period') }
          end
        end
      end
    end
  end