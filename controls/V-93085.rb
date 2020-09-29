# encoding: UTF-8

control "V-93085" do
  title "Windows Server 2019 Restore files and directories user right must only
be assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Restore files and directories\" user right can
circumvent file and directory permissions and could allow access to sensitive
data. It could also be used to overwrite more current data."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups other than the following are granted the
\"Restore files and directories\" user right, this is a finding:

    - Administrators

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs other than the following are granted the \"SeRestorePrivilege\"
user right, this is a finding:

    S-1-5-32-544 (Administrators)

    If an application requires this user right, this would not be a finding.

    Vendor documentation must support the requirement for having the user right.

    The requirement must be documented with the ISSO.

    The application account must meet requirements for application account
passwords, such as length (WN19-00-000050) and required frequency of changes
(WN19-00-000060)."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Restore
files and directories\" to include only the following accounts or groups:

    - Administrators"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93085'
  tag 'rid': 'SV-103173r1_rule'
  tag 'stig_id': 'WN19-UR-000210'
  tag 'fix_id': 'F-99331r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
    describe security_policy do
     its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
  end
 end
end

