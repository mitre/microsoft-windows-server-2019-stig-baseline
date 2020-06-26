# encoding: UTF-8

control "V-93463" do
  title "Windows Server 2019 minimum password length must be configured to 14 characters."
  desc  "Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for the \"Minimum password length,\" is less than \"14\" characters, this is a finding.

    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"MinimumPasswordLength\" is less than \"14\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Minimum password length\" to \"14\" characters."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000078-GPOS-00046"
  tag gid: "V-93463"
  tag rid: "SV-103549r1_rule"
  tag stig_id: "WN19-AC-000070"
  tag fix_id: "F-99707r1_fix"
  tag cci: ["CCI-000205"]
  tag nist: ["IA-5 (1) (a)", "Rev_4"]

  describe security_policy do
    its('MinimumPasswordLength') { should be >= input('minimum_password_length')}
  end
end