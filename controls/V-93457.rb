# encoding: UTF-8

control 'V-93457' do
  title 'Windows Server 2019 outdated or unused accounts must be removed or disabled.'
  desc  'Outdated or unused accounts provide penetration points that may go undetected. Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.'
  desc  'rationale', ''
  desc  'check', "Open \"Windows PowerShell\".

    Domain Controllers:
    Enter \"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00\"
    This will return accounts that have not been logged on to for 35 days, along with various attributes such as the Enabled status and LastLogonDate.

    Member servers and standalone systems:
    Copy or enter the lines below to the PowerShell window and enter. (Entering twice may be required. Do not include the quotes at the beginning and end of the query.)
    \"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
     $user = ([ADSI]$_.Path)
     $lastLogin = $user.Properties.LastLogin.Value
     $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
     if ($lastLogin -eq $null) {
     $lastLogin = 'Never'
     }
     Write-Host $user.Name $lastLogin $enabled
    }\"
    This will return a list of local accounts with the account name, last logon, and if the account is enabled (True/False).
    For example: User1 10/31/2015 5:49:56 AM True
    Review the list of accounts returned by the above queries to determine the finding validity for each account reported.

    Exclude the following accounts:
    - Built-in administrator account (Renamed, SID ending in 500)
    - Built-in guest account (Renamed, Disabled, SID ending in 501)
    - Application accounts

    If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

    Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO."
  desc  'fix', 'Regularly review accounts to determine if they are still active. Remove or disable accounts that have not been used in the last 35 days.'
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-93457'
  tag rid: 'SV-103543r1_rule'
  tag stig_id: 'WN19-00-000190'
  tag fix_id: 'F-99701r1_fix'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e', 'Rev_4']
  
  
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  age = input('unused_account_age')
  untracked_accounts = []

  if domain_role == '4' || domain_role == '5'

    excluded_accounts_domain_check = json(command: 'Get-ADUser -Filter * | Where {($_.SID -like "*-500") -or ($_.SID -like "*-501")} | Select Name | ConvertTo-Json').params
    excluded_accounts_domain = []
    excluded_accounts_domain_check.each { |account| excluded_accounts_domain << account["Name"] }

    ad_accounts = json({ command: "Search-ADAccount -AccountInactive -UsersOnly -Timespan #{age}.00:00:00 | Where -Property Enabled -eq $True | Select -ExpandProperty Name | ConvertTo-Json" }).params
    unless ad_accounts.empty?
      case ad_accounts
      when String
        (ad_account = []) << ad_accounts
        untracked_accounts = ad_account - input('application_accounts_domain') - excluded_accounts_domain
      when Array
        untracked_accounts = ad_accounts - input('application_accounts_domain') - excluded_accounts_domain
      end
    end

    describe 'AD Accounts' do
      it "AD should not have any Accounts that are Inactive over #{age} days" do
        failure_message = "User(s) that have not logged into system in #{age} days #{untracked_accounts}"
        expect(untracked_accounts).to be_empty, failure_message
      end
    end

  else

    excluded_accounts_local_check = json(command: 'Get-LocalUser | Where {($_.SID -like "*-500") -or ($_.SID -like "*-501")} | Select Name | ConvertTo-Json').params
    excluded_accounts_local = []
    excluded_accounts_local_check.each do |account|
      excluded_accounts_local << account["Name"]
    end

    local_accounts = json({ command: "Get-LocalUser | Where-Object {$_.Enabled -eq 'True' -and $_.Lastlogon -le (Get-Date).AddDays(-#{age}) } | Select -ExpandProperty Name | ConvertTo-Json" }).params

    unless local_accounts.empty?
      case local_accounts
      when String
        (local_account = []) << local_accounts
        untracked_accounts = local_account - input('application_accounts_local') - excluded_accounts_local
      when Array
        untracked_accounts = local_accounts - input('application_accounts_local') - excluded_accounts_local
      end
    end

    describe 'Inactive account or accounts exists' do
      it 'Server should not have inactive accounts' do
        failure_message = "User(s) that have not logged into system in #{age} days: #{local_accounts}"
        expect(local_accounts).to be_empty, failure_message
      end
    end
  end
end