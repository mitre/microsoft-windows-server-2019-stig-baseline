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

#____________________________JB_____________________________________________________

  # Critical Input by person running profile
  emergency_accounts_domain = input('emergency_accounts_domain')
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if emergency_accounts_domain.empty?
    describe 'There are no Emergency Account listed for this Control' do
      skip 'This becomes a manual check if the input emergency_accounts_domain is not assigned a value'
    end
  else
    if domain_role == '4' || domain_role == '5'
      emergency_accounts_domain.each do |user|
        # Gets raw format of creation date
        raw_day_created = powershell("Get-ADUser -Identity #{user} -Properties Created | Findstr /i 'Created'").stdout.strip
        # If statement checks for "/" in output to see where the first number for month starts
       if raw_day_created[21] == '/'
          clean_month_created = raw_day_created[20]
       else
          clean_month_created = raw_day_created[20..21]
       end
        # If statement checks for "/" in output to see where the first number for Day starts
        if raw_day_created[21] == '/' && raw_day_created[23] == '/'
          clean_day_created = raw_day_created[22]
        elsif raw_day_created[21] != '/' && raw_day_created[24] == '/'
          clean_day_created = raw_day_created[23]
        elsif raw_day_created[21] == '/' && raw_day_created[22] != '/' && raw_day_created[23] != '/' && raw_day_created[24] == '/'
          clean_day_created = raw_day_created[22..23]
        elsif raw_day_created[21] != '/' && raw_day_created[22] == '/' && raw_day_created[23] != '/' && raw_day_created[24] != '/' && raw_day_created[25] == '/'
          clean_day_created = raw_day_created[23..24]
         end
        # If statement checks for last "/" before year starts
        if raw_day_created[23] == '/'
          clean_year_created = raw_day_created[24..27]
        elsif raw_day_created[24] == '/'
          clean_year_created = raw_day_created[25..28]
        elsif raw_day_created[25] == '/'
          clean_year_created = raw_day_created[26..29]
         end
        # date created by starts setup as dd/mm/yyyy
        date_created = clean_day_created + '/' + clean_month_created + '/' + clean_year_created

        # Gets raw format of expiration date
        raw_day_expire_date = powershell("Get-ADUser -Identity #{user} -Properties AccountExpirationDate | Findstr /i 'AccountExpirationDate'").stdout.strip

        # If statement checks for "/" in output to see where the first number for month starts
        if raw_day_expire_date[25] == '/'
           clean_month_expire_date = raw_day_expire_date[24]
        else
           clean_month_expire_date = raw_day_expire_date[24..25]
        end
        # If statement checks for "/" in output to see where the first number for Day starts
        if raw_day_expire_date[25] == '/' && raw_day_expire_date[27] == '/'
          clean_day_expire_date = raw_day_expire_date[26]
        elsif raw_day_expire_date[25] != '/' && raw_day_expire_date[28] == '/'
          clean_day_expire_date = raw_day_expire_date[27]
        elsif raw_day_expire_date[25] == '/' && raw_day_expire_date[26] != '/' && raw_day_expire_date[27] != '/' && raw_day_expire_date[28] == '/'
          clean_day_expire_date = raw_day_expire_date[26..27]
        elsif raw_day_expire_date[25] != '/' && raw_day_expire_date[26] == '/' && raw_day_expire_date[27] != '/' && raw_day_expire_date[28] != '/' && raw_day_expire_date[29] == '/'
          clean_day_expire_date = raw_day_expire_date[27..28]
         end
        # If statement checks for last "/" before year starts
        if raw_day_expire_date[27] == '/'
          clean_year_expire_date = raw_day_expire_date[28..31]
        elsif raw_day_expire_date[28] == '/'
          clean_year_expire_date = raw_day_expire_date[29..32]
        elsif raw_day_expire_date[29] == '/'
          clean_year_expire_date = raw_day_expire_date[30..33]
         end

        # date expire setup as dd/mm/yyyy
        date_expires = clean_day_expire_date + '/' + clean_month_expire_date + '/' + clean_year_expire_date
        # Determines the number of days difference
        date_expires_minus_password_last_set = DateTime.parse(date_expires).mjd - DateTime.parse(date_created).mjd

        if date_expires_minus_password_last_set <= 3
          describe "Emergency Account is within 3 days since creation and expiration: #{user}" do
            skip "Emergency Account is within 3 days since creation and expiration: #{user}"
          end
        else
          describe 'Account Expiration' do
            it "Emergency Account #{user} Creation date and Expiration date is" do
              failure_message = 'more than 3 days'
              expect(date_expires_minus_password_last_set).to be_empty, failure_message
            end
          end
        end
      end
    end
 end

  # Critical Input to allow for Control to pass
  emergency_account_local = input('emergency_account_local')
  if domain_role != '4' || domain_role != '5'
    if emergency_account_local.empty?
      describe 'There are no accounts in input emergency_account_local, nothing will run' do
        skip 'There are no accounts in input emergency_account_local, nothing will run'
      end
    else
      emergency_account_local.each do |user|
        # Gets Raw Account Expiration Date for Local Account
        get_account_expires = powershell("Get-LocalUser -name #{user}  | Select-Object AccountExpires").stdout.strip

        # Gets Local Accounts Month of Expiration Date
        if get_account_expires[47] == '/'
           clean_account_expires_month = get_account_expires[46]
        else
           clean_account_expires_month = get_account_expires[46..47]
        end

        # If statement checks for "/" in output to see where the first number for Day starts
        if get_account_expires[47] == '/' && get_account_expires[49] == '/'
          clean_account_expires_day = get_account_expires[48]
        elsif get_account_expires[47] != '/' && get_account_expires[50] == '/'
          clean_account_expires_day = get_account_expires[49]
        elsif get_account_expires[47] == '/' && get_account_expires[48] != '/' && get_account_expires[49] != '/' && get_account_expires[50] == '/'
          clean_account_expires_day = get_account_expires[48..49]
        elsif get_account_expires[47] != '/' && get_account_expires[48] == '/' && get_account_expires[49] != '/' && get_account_expires[50] != '/' && get_account_expires[51] == '/'
          clean_account_expires_day = get_account_expires[49..50]
        end

        # If statement checks for last "/" before year starts
        if get_account_expires[49] == '/'
          clean_account_expires_year = get_account_expires[50..53]
        elsif get_account_expires[50] == '/'
          clean_account_expires_year = get_account_expires[51..54]
        elsif get_account_expires[51] == '/'
          clean_account_expires_year = get_account_expires[52..55]
        end

        # date account expires by starts setup as dd/mm/yyyy
        date_account_expires = clean_account_expires_day + '/' + clean_account_expires_month + '/' + clean_account_expires_year

        # Gets Raw Password Last Set Date for Local Account
        get_password_last_set = powershell("Get-LocalUser -name #{user} | Select-Object PasswordLastSet").stdout.strip
        # Gets Local Accounts Month of Expiration Date
        if get_password_last_set[43] == '/'
            clean_account_last_pass_month = get_password_last_set[42]
        else
            clean_account_last_pass_month = get_password_last_set[42..43]
        end

        # If statement checks for "/" in output to see where the first number for Day starts
        if get_password_last_set[43] == '/' && get_password_last_set[45] == '/'
          clean_account_last_pass_day = get_password_last_set[44]
        elsif get_password_last_set[43] != '/' && get_password_last_set[46] == '/'
          clean_account_last_pass_day = get_password_last_set[45]
        elsif get_password_last_set[43] == '/' && get_password_last_set[44] != '/' && get_password_last_set[45] != '/' && get_password_last_set[46] == '/'
          clean_account_last_pass_day = get_password_last_set[44..45]
        elsif get_password_last_set[43] != '/' && get_password_last_set[44] == '/' && get_password_last_set[45] != '/' && get_password_last_set[46] != '/' && get_password_last_set[47] == '/'
          clean_account_last_pass_day = get_password_last_set[45..46]
        end

        # If statement checks for last "/" before year starts
        if get_password_last_set[45] == '/'
          clean_account_last_pass_year = get_password_last_set[46..49]
        elsif get_password_last_set[46] == '/'
          clean_account_last_pass_year = get_password_last_set[47..50]
        elsif get_password_last_set[47] == '/'
          clean_account_last_pass_year = get_password_last_set[48..51]
        end

        # date expire setup as dd/mm/yyyy
        date_expire_last_set = clean_account_last_pass_day + '/' + clean_account_last_pass_month + '/' + clean_account_last_pass_year
        # Determines the number of days difference
        date_expires_minus_password_last_set = DateTime.parse(date_account_expires).mjd - DateTime.parse(date_expire_last_set).mjd

        if date_expires_minus_password_last_set <= 3
          describe "Emergency Account is within 3 days since creation and expiration: #{user}" do
            skip "Emergency Account is within 3 days since creation and expiration: #{user}"
          end
        else
          describe 'Account Expiration' do
            it "Emergency Account #{user} Expiration date and Password Last Set is" do
              failure_message = 'more than 3 days'
              expect(date_expires_minus_password_last_set).to be_empty, failure_message
            end
          end
        end
      end
   end
 end
end

#____________________________SK_____________________________________________________

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  
  if domain_role == '4' || domain_role == '5' # Domain Controller
    emergency_accounts_list = input('emergency_accounts_domain')
    if emergency_accounts_list.empty?
      impact 0.0
      describe 'There are no Emergency Account listed for this Control' do
        skip 'This becomes a manual check if the input emergency_accounts_domain is not assigned a value'
      end
    else
      emergency_accounts = []
      emergency_accounts_list.each do |emergency_account|
        emergency_accounts << json({ command: "Get-ADUser -Identity #{emergency_account} -Properties WhenCreated, AccountExpirationDate | Select-Object -Property SamAccountName, @{Name=”WhenCreated”;Expression={$_.WhenCreated.ToString(“yyyy-MM-dd”)}}, @{Name=”AccountExpirationDate”;Expression={$_.AccountExpirationDate.ToString(“yyyy-MM-dd”)}}| ConvertTo-Json"}).params
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

  else # Standalone and member servers
    emergency_accounts_list = input('emergency_accounts_local')
    if emergency_accounts_list.empty?
      impact 0.0
      describe 'There are no Emergency Account listed for this Control' do
        skip 'This becomes a manual check if the input emergency_accounts_domain is not assigned a value'
      end
    else
      emergency_accounts = []
      emergency_accounts_list.each do |emergency_account|
        emergency_accounts << json({ command: "Get-LocalUser -Name #{emergency_account} | Select-Object -Property Name, @{Name=”PasswordLastSet”;Expression={$_.PasswordLastSet.ToString(“yyyy-MM-dd”)}}, @{Name=”AccountExpires”;Expression={$_.AccountExpires.ToString(“yyyy-MM-dd”)}} | ConvertTo-Json"}).params
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
