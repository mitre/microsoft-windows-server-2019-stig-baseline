# encoding: UTF-8

control "V-93439" do
  title "Windows Server 2019 accounts must require passwords."
  desc  "The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources. Accounts on a system must require passwords."
  desc  "rationale", ""
  desc  "check", "Review the password required status for enabled user accounts.
    Open \"PowerShell\".

    Domain Controllers:
    Enter \"Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled\".
    Exclude disabled accounts (e.g., DefaultAccount, Guest) and Trusted Domain Objects (TDOs).
    If \"Passwordnotrequired\" is \"True\" or blank for any enabled user account, this is a finding.

    Member servers and standalone systems:
    Enter 'Get-CimInstance -Class Win32_Useraccount -Filter \"PasswordRequired=False and LocalAccount=True\" | FT Name, PasswordRequired, Disabled, LocalAccount'.
    Exclude disabled accounts (e.g., DefaultAccount, Guest).
    If any enabled user accounts are returned with a \"PasswordRequired\" status of \"False\", this is a finding."
  desc  "fix", "Configure all enabled accounts to require passwords.
    The password required flag can be set by entering the following on a command line: \"Net user [username] /passwordreq:yes\", substituting [username] with the name of the user account."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000104-GPOS-00051"
  tag gid: "V-93439"
  tag rid: "SV-103525r2_rule"
  tag stig_id: "WN19-00-000200"
  tag fix_id: "F-99683r1_fix"
  tag cci: ["CCI-000764"]
  tag nist: ["IA-2", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    ad_accounts = json({ command: "Get-ADUser -Filter \"(Enabled -eq $true) -And (PasswordNotRequired -eq $true)\" | Select -ExpandProperty Name | ConvertTo-Json" }).params
    describe 'AD Accounts' do
      it 'AD should not have any Accounts that have Password Not Required' do
      failure_message = "Users that have Password Not Required: #{ad_accounts}"
      expect(ad_accounts).to be_empty, failure_message
      end
    end
  else
    local_accounts = json({ command: "Get-CimInstance -Class Win32_Useraccount -Filter 'PasswordRequired=False and LocalAccount=True and Disabled=False' | Select -ExpandProperty Name | ConvertTo-Json" }).params
    describe "Account or Accounts exists" do
      it 'Server should not have Accounts with No Password Set' do
        failure_message = "User or Users that have no Password Set: #{local_accounts}" 
        expect(local_accounts).to be_empty, failure_message
      end
    end
  end
end