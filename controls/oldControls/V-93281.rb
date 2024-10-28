# encoding: UTF-8

control "V-93281" do
  title "Windows Server 2019 built-in administrator account must be renamed."
  desc  "The built-in administrator account is a well-known account subject to attack. Renaming this account to an unidentified name improves the protection of this account and the system."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

    If the value for \"Accounts: Rename administrator account\" is not set to a value other than \"Administrator\", this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

    If \"NewAdministratorName\" is not something other than \"Administrator\" in the file, this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Accounts: Rename administrator account\" to a name other than \"Administrator\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93281"
  tag rid: "SV-103369r1_rule"
  tag stig_id: "WN19-SO-000030"
  tag fix_id: "F-99527r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe security_policy do
    its('NewAdministratorName') { should_not cmp "Administrator" }
  end
end
