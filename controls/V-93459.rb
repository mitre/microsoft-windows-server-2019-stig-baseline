# encoding: UTF-8

control "V-93459" do
  title "Windows Server 2019 must have the built-in Windows password complexity policy enabled."
  desc  "The use of complex passwords increases their strength against attack. The built-in Windows password complexity policy requires passwords to contain at least three of the four types of characters (numbers, uppercase and lowercase letters, and special characters) and prevents the inclusion of user names or parts of user names."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.
    
    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for \"Password must meet complexity requirements\" is not set to \"Enabled\", this is a finding.

    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"PasswordComplexity\" equals \"0\" in the file, this is a finding.

    Note: If an external password filter is in use that enforces all four character types and requires this setting to be set to \"Disabled\", this would not be considered a finding. If this setting does not affect the use of an external password filter, it must be enabled for fallback purposes."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Password must meet complexity requirements\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000069-GPOS-00037"
  tag satisfies: ["SRG-OS-000069-GPOS-00037", "SRG-OS-000070-GPOS-00038", "SRG-OS-000071-GPOS-00039", "SRG-OS-000266-GPOS-00101"]
  tag gid: "V-93459"
  tag rid: "SV-103545r1_rule"
  tag stig_id: "WN19-AC-000080"
  tag fix_id: "F-99703r1_fix"
  tag cci: ["CCI-000192", "CCI-000193", "CCI-000194", "CCI-001619"]
  tag nist: ["IA-5 (1) (a)", "IA-5 (1) (a)", "IA-5 (1) (a)", "IA-5 (1) (a)", "Rev_4"]

  describe security_policy do
    its('PasswordComplexity') { should eq input('enable_password_complexity') }
  end
end