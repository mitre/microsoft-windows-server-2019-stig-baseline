# encoding: UTF-8

control "V-93047" do
  title "Windows Server 2019 Enable computer and user accounts to be trusted
for delegation user right must not be assigned to any groups or accounts on
domain-joined member servers and standalone systems."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Enable computer and user accounts to be trusted for delegation\" user
right allows the \"Trusted for Delegation\" setting to be changed. This could
allow unauthorized users to impersonate other users."
  desc  "rationale", ""
  desc  'check', "This applies to member servers and standalone systems. A separate version
applies to domain controllers.

    Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups are granted the \"Enable computer and user
accounts to be trusted for delegation\" user right, this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs are granted the \"SeEnableDelegationPrivilege\" user right,
this is a finding."
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> User Rights
Assignment >> \"Enable computer and user accounts to be trusted for
delegation\" to be defined but containing no entries (blank)."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93047'
  tag 'rid': 'SV-103135r1_rule'
  tag 'stig_id': 'WN19-MS-000130'
  tag 'fix_id': 'F-99293r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  end
  if domain_role == '4' || domain_role == '5'
      impact 0.0
      describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers' do
       skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers'
      end
  else
    describe security_policy do
     its('SeEnableDelegationPrivilege') { should eq [] }
  end
 end
end

