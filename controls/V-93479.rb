# encoding: UTF-8

control "V-93479" do
  title "Windows Server 2019 password history must be configured to 24 passwords remembered."
  desc  "A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is \"24\" for Windows domain systems. DoD has decided this is the appropriate value for all Windows systems."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.
    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for \"Enforce password history\" is less than \"24\" passwords remembered, this is a finding.

    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"PasswordHistorySize\" is less than \"24\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Enforce password history\" to \"24\" passwords remembered."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000077-GPOS-00045"
  tag gid: "V-93479"
  tag rid: "SV-103565r1_rule"
  tag stig_id: "WN19-AC-000040"
  tag fix_id: "F-99723r1_fix"
  tag cci: ["CCI-000200"]
  tag nist: ["IA-5 (1) (e)", "Rev_4"]

  describe security_policy do
    its('PasswordHistorySize') { should be >= input('password_history_size') }
  end
end