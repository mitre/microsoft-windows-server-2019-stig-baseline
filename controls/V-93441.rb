# encoding: UTF-8

control "V-93441" do
  title "Windows Server 2019 Active Directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), Personal Identity Verification (PIV)-compliant hardware token, or Alternate Logon Token (ALT) for user authentication."
  desc  "Smart cards such as the CAC support a two-factor authentication technique. This provides a higher level of trust in the asserted identity than use of the username and password for authentication."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.

    Open \"PowerShell\".
    Enter the following:
    \"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name\"
    (\"DistinguishedName\" may be substituted for \"Name\" for more detailed output.)
    If any user accounts, including administrators, are listed, this is a finding.

    Alternately:
    To view sample accounts in \"Active Directory Users and Computers\" (available from various menus or run \"dsa.msc\"):
    Select the Organizational Unit (OU) where the user accounts are located. (By default, this is the Users node; however, accounts may be under other organization-defined OUs.)
    Right-click the sample user account and select \"Properties\".
    Select the \"Account\" tab.
    If any user accounts, including administrators, do not have \"Smart card is required for interactive logon\" checked in the \"Account Options\" area, this is a finding."
  desc  "fix", "Configure all user accounts, including administrator accounts, in Active Directory to enable the option \"Smart card is required for interactive logon\".

    Run \"Active Directory Users and Computers\" (available from various menus or run \"dsa.msc\"):
    Select the OU where the user accounts are located. (By default this is the Users node; however, accounts may be under other organization-defined OUs.)
    Right-click the user account and select \"Properties\".
    Select the \"Account\" tab.
    Check \"Smart card is required for interactive logon\" in the \"Account Options\" area."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000105-GPOS-00052"
  tag satisfies: ["SRG-OS-000105-GPOS-00052", "SRG-OS-000106-GPOS-00053", "SRG-OS-000107-GPOS-00054", "SRG-OS-000108-GPOS-00055", "SRG-OS-000375-GPOS-00160"]
  tag gid: "V-93441"
  tag rid: "SV-103527r1_rule"
  tag stig_id: "WN19-DC-000310"
  tag fix_id: "F-99685r1_fix"
  tag cci: ["CCI-000765", "CCI-000766", "CCI-000767", "CCI-000768", "CCI-001948"]
  tag nist: ["IA-2 (1)", "IA-2 (2)", "IA-2 (3)", "IA-2 (4)", "IA-2 (11)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    accounts = json(command: "Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | Select -ExpandProperty Name | ConvertTo-Json").params
    describe 'Accounts without smartcard logon required' do
      it 'Accounts must be configured to require the use of a CAC, PIV or ALT' do
        failure_message = "#{accounts}"
        expect(accounts).to be_empty, failure_message
      end
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end