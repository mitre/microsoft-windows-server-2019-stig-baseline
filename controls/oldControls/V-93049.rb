# encoding: UTF-8

control "V-93049" do
  title "Windows Server 2019 Access Credential Manager as a trusted caller user
right must not be assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Access Credential Manager as a trusted caller\" user
right may be able to retrieve the credentials of other accounts from Credential
Manager."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups are granted the \"Access Credential Manager as a
trusted caller\" user right, this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs are granted the \"SeTrustedCredManAccessPrivilege\" user right,
this is a finding."
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> User Rights
Assignment >> \"Access Credential Manager as a trusted caller\" to be defined
but containing no entries (blank)."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93049'
  tag 'rid': 'SV-103137r1_rule'
  tag 'stig_id': 'WN19-UR-000010'
  tag 'fix_id': 'F-99295r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]


  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
    describe security_policy do
     its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
 end
end

