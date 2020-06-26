# encoding: UTF-8

control "V-93497" do
  title "Windows Server 2019 must have the built-in guest account disabled."
  desc  "A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.
    If the value for \"Accounts: Guest account status\" is not set to \"Disabled\", this is a finding.
    
    For server core installations, run the following command:
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    If \"EnableGuestAccount\" equals \"1\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Accounts: Guest account status\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000121-GPOS-00062"
  tag gid: "V-93497"
  tag rid: "SV-103583r1_rule"
  tag stig_id: "WN19-SO-000010"
  tag fix_id: "F-99741r1_fix"
  tag cci: ["CCI-000804"]
  tag nist: ["IA-8", "Rev_4"]

  describe security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end