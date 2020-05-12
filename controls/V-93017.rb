# encoding: UTF-8

control "V-93017" do
  title "Windows Server 2019 Allow log on locally user right must only be
assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Allow log on locally\" user right can log on
interactively to a system."
  desc  "rationale", ""
  desc 'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups other than the following are granted the \"Allow
log on locally\" user right, this is a finding:

    - Administrators

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs other than the following are granted the
\"SeInteractiveLogonRight\" user right, this is a finding:

    S-1-5-32-544 (Administrators)

    If an application requires this user right, this would not be a finding.

    Vendor documentation must support the requirement for having the user right.

    The requirement must be documented with the ISSO.

    The application account must meet requirements for application account
passwords, such as length (WN19-00-000050) and required frequency of changes
(WN19-00-000060)."
  desc 'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Allow log
on locally\" to include only the following accounts or groups:

    - Administrators"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-93017'
  tag 'rid': 'SV-103105r1_rule'
  tag 'stig_id': 'WN19-UR-000030'
  tag 'fix_id': 'F-99263r1_fix'
  tag 'cci': ["CCI-000213"]
  tag 'nist': ["AC-3", "Rev_4"]

    describe security_policy do
      its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
    end
end

