# encoding: UTF-8

control "V-93471" do
  title "Windows Server 2019 minimum password age must be configured to at least one day."
  desc  "Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.
    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for the \"Minimum password age\" is set to \"0\" days (\"Password can be changed immediately\"), this is a finding.

    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"MinimumPasswordAge\" equals \"0\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Minimum password age\" to at least \"1\" day."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000075-GPOS-00043"
  tag gid: "V-93471"
  tag rid: "SV-103557r1_rule"
  tag stig_id: "WN19-AC-000060"
  tag fix_id: "F-99715r1_fix"
  tag cci: ["CCI-000198"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]

  describe security_policy do
    its('MinimumPasswordAge') { should be >= input('minimum_password_age') }
  end
end