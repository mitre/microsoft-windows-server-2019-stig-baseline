# encoding: UTF-8

control "V-93465" do
  title "Windows Server 2019 reversible password encryption must be disabled."
  desc  "Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the passwords, which are easily compromised. For this reason, this policy must never be enabled."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.
    If the value for \"Store passwords using reversible encryption\" is not set to \"Disabled\", this is a finding.

    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"ClearTextPassword\" equals \"1\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> \"Store passwords using reversible encryption\" to \"Disabled\"."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000073-GPOS-00041"
  tag gid: "V-93465"
  tag rid: "SV-103551r1_rule"
  tag stig_id: "WN19-AC-000090"
  tag fix_id: "F-99709r1_fix"
  tag cci: ["CCI-000196"]
  tag nist: ["IA-5 (1) (c)", "Rev_4"]

  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end