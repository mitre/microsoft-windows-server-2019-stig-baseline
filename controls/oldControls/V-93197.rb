# encoding: UTF-8

control "V-93197" do
  title "Windows Server 2019 Manage auditing and security log user right must
only be assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Manage auditing and security log\" user right can
manage the security log and change auditing configurations. This could be used
to clear evidence of tampering."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups other than the following are granted the \"Manage
auditing and security log\" user right, this is a finding.

    - Administrators

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs other than the following are granted the
\"SeSecurityPrivilege\" user right, this is a finding:

    S-1-5-32-544 (Administrators)

    If the organization has an Auditors group, the assignment of this group to
the user right would not be a finding.

    If an application requires this user right, this would not be a finding.

    Vendor documentation must support the requirement for having the user right.

    The requirement must be documented with the ISSO.

    The application account must meet requirements for application account
passwords, such as length (WN19-00-000050) and required frequency of changes
(WN19-00-000060)."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Manage
auditing and security log\" to include only the following accounts or groups:

    - Administrators"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000057-GPOS-00027'
  tag 'satisfies': ["SRG-OS-000057-GPOS-00027", "SRG-OS-000058-GPOS-00028",
"SRG-OS-000059-GPOS-00029", "SRG-OS-000063-GPOS-00032",
"SRG-OS-000337-GPOS-00129"]
  tag 'gid': 'V-93197'
  tag 'rid': 'SV-103285r1_rule'
  tag 'stig_id': 'WN19-UR-000170'
  tag 'fix_id': 'F-99443r1_fix'
  tag 'cci': ["CCI-000162", "CCI-000163", "CCI-000164", "CCI-000171",
"CCI-001914"]
  tag 'nist': ["AU-9", "AU-9", "AU-9", "AU-12 b", "AU-12 (3)", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
    describe security_policy do
     its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
    end
  end
end

