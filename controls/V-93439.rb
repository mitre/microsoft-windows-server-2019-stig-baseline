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

  # SK: Copied from Windows 2012 V-7002
  # Q: Password required condition removed - review modifications
  # QJ: Test pending | Could use guidance

  # returns a hash of {'Enabled' => 'true' } 
  is_domain_controller = json({ command: 'Get-ADDomainController | Select Enabled | ConvertTo-Json' })

  if (is_domain_controller['Enabled'] == true)
    list_of_accounts = json({ command: "Get-ADUser -Filter * -Properties PasswordNotRequired | Where-Object {$_.PasswordNotRequired -eq 'True' -and $_.Enabled -eq 'True'} Select -ExpandProperty Name | ConvertTo-Json" })

    #list_of_accounts = json({ command: "Get-ADUser -Filter * -Properties PasswordNotRequired | (Where PasswordNotRequired -eq True) -and (Where Enabled -eq True) | ConvertTo-Json" })
    ad_accounts = list_of_accounts.params
  
    # EXPERIMENT
    # state = powershell("get-aduser -Filter {(Passwordnotrequired -eq $true) -and (Enabled -eq $true)} | ConvertTo-Json").stdout.strip
    # subject { state }
    # it { should_not eq "Enabled"}

    # certs = command("Get-ChildItem -Path Cert:\\LocalMachine\\My | ConvertTo-JSON").stdout
    # describe "The domain controller's  server certificate" do
    #   subject { certs }
    #   it { should_not cmp '' }
    # end
    # OJ: Sugestion
    # ad_accounts = json({ command: "get-aduser -Filter {(Passwordnotrequired -eq $true) -and (Enabled -eq $true)} | ConvertTo-Json" }).params
    #print(ad_accounts)

    # require 'pry'; binding.pry
    describe 'AD Accounts' do
      it 'AD should not have any Accounts that have Password Not Required' do
      failure_message = "Users that have Password Not Required #{ad_accounts}"
      expect(ad_accounts).to be_empty, failure_message
      end
    end
  end

  # QJ: Need to have a specific condition that needs to be met by member and standalone servers
  if (is_domain_controller.params == {} )
    local_users = json({ command: "Get-CimInstance -Class Win32_Useraccount -Filter PasswordRequired=False and LocalAccount=True | Select -ExpandProperty Name | ConvertTo-Json" })
    local_users_list = local_users.params
    if (local_users_list == ' ')
      impact 0.0
      describe 'The system does not have any accounts with a Password set, control is NA' do
        skip 'The system does not have any accounts with a Password set,, controls is NA'
      end
    else
      describe "Account or Accounts exists" do
        it 'Server should not have Accounts with No Password Set' do
          failure_message = "User or Users #{local_users_list} have no Password Set" 
          expect(local_users_list).to be_empty, failure_message
        end
      end
    end
  end

end