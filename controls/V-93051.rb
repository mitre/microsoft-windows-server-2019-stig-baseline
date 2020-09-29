# encoding: UTF-8

control "V-93051" do
  title "Windows Server 2019 Act as part of the operating system user right
must not be assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Act as part of the operating system\" user right can
assume the identity of any user and gain access to resources that the user is
authorized to access. Any accounts with this right can take complete control of
a system."
  desc  "rationale", ""
  desc 'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups (to include administrators), are granted the
\"Act as part of the operating system\" user right, this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs are granted the \"SeTcbPrivilege\" user right, this is a
finding.

    If an application requires this user right, this would not be a finding.

    Vendor documentation must support the requirement for having the user right.

    The requirement must be documented with the ISSO.

    The application account must meet requirements for application account
passwords, such as length (WN19-00-000050) and required frequency of changes
(WN19-00-000060).

    Passwords for accounts with this user right must be protected as highly
privileged accounts."
  desc 'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> User Rights
Assignment >> \"Act as part of the operating system\" to be defined but
containing no entries (blank)."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93051'
  tag 'rid': 'SV-103139r1_rule'
  tag 'stig_id': 'WN19-UR-000020'
  tag 'fix_id': 'F-99297r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]


  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
    describe security_policy do
     its('SeTcbPrivilege') { should eq [] }
  end
 end
end

