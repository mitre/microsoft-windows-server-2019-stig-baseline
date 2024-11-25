control 'SV-205658' do
  title 'Windows Server 2019 passwords must be configured to expire.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', %q(Review the password never expires status for enabled user accounts.

Open "PowerShell".

Domain Controllers:

Enter "Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled".

Exclude application accounts, disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

If any enabled user accounts are returned with a "PasswordNeverExpires" status of "True", this is a finding.

Member servers and standalone or nondomain-joined systems:

Enter 'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'.

Exclude application accounts and disabled accounts (e.g., DefaultAccount, Guest).

If any enabled user accounts are returned with a "PasswordExpires" status of "False", this is a finding.)
  desc 'fix', 'Configure all enabled user account passwords to expire.

Uncheck "Password never expires" for all enabled user accounts in Active Directory Users and Computers for domain accounts and Users in Computer Management for member servers and standalone or nondomain-joined systems. Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-205658'
  tag rid: 'SV-205658r1000126_rule'
  tag stig_id: 'WN19-00-000210'
  tag fix_id: 'F-5923r857296_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  untracked_accounts = []

  if ['4', '5'].include?(domain_role)
    ad_accounts = json({ command: "Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.PasswordNeverExpires -eq 'True' -and $_.Enabled -eq 'True'} | Select -ExpandProperty Name | ConvertTo-Json" }).params

    application_accounts = input('application_accounts_domain')
    excluded_accounts = input('excluded_accounts_domain')

    unless ad_accounts.empty?
      ad_accounts = [ad_accounts] if ad_accounts.instance_of?(String)
      untracked_accounts = ad_accounts - application_accounts - excluded_accounts
    end

    describe 'Untracked Accounts' do
      it 'No Enabled Domain Account should be set to have Password Never Expire' do
        failure_message = "Users Accounts are set to Password Never Expire: #{untracked_accounts}"
        expect(untracked_accounts).to be_empty, failure_message
      end
    end
  else
    local_accounts = json({ command: "Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordExpires=False and LocalAccount=True and Disabled=False' | Select -ExpandProperty Name | ConvertTo-Json" }).params

    application_accounts = input('application_accounts_local')

    excluded_accounts = input('excluded_accounts_local')

    unless local_accounts.empty?
      local_accounts = [local_accounts] if local_accounts.instance_of?(String)
      untracked_accounts = local_accounts - application_accounts - excluded_accounts
    end

    describe 'Account or Accounts exists' do
      it 'Server should not have Accounts with Password Never Expire' do
        failure_message = "User or Users have Password set to not expire: #{untracked_accounts}"
        expect(untracked_accounts).to be_empty, failure_message
      end
    end
  end
end
