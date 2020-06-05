# encoding: UTF-8

control "V-93477" do
  title "Windows Server 2019 maximum password age must be configured to 60 days or less."
  desc  "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.
    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for the \"Maximum password age\" is greater than \"60\" days, this is a finding.
    If the value is set to \"0\" (never expires), this is a finding.
    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"MaximumPasswordAge\" is greater than \"60\" or equal to \"0\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Maximum password age\" to \"60\" days or less (excluding \"0\", which is unacceptable)."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000076-GPOS-00044"
  tag gid: "V-93477"
  tag rid: "SV-103563r1_rule"
  tag stig_id: "WN19-AC-000050"
  tag fix_id: "F-99721r1_fix"
  tag cci: ["CCI-000199"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]

  # SK: Copied from Windows 2012 V-1104
  # SK: Test - passed for Server with Desktop Experience
  # Q: Server Core Installation test pending
  # QJ: Check if hardcoding the value would be okay

  describe security_policy do
  #  its('MaximumPasswordAge') { should be <= input('max_pass_age') }
    its('MaximumPasswordAge') { should be <= 60 }
  end
  describe security_policy do
    its('MaximumPasswordAge') { should be > 0 }
  end

  # QJ: Need to clean up the test output, adding a subject doesn't seem to help, thoughts?

  password_age_range = (1..60).step(1).to_a
  describe 'Maximum password age to 60 days or less (excluding 0, which is unacceptable)' do
    subject { security_policy }
    its('MaximumPasswordAge') { should be_in password_age_range }
  end

end