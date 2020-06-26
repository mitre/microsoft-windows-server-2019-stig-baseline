# encoding: UTF-8

control "V-93389" do
  title "Windows Server 2019 must not have the TFTP Client installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system."
  desc  "rationale", ""
  desc  "check", "Open \"PowerShell\".

    Enter \"Get-WindowsFeature | Where Name -eq TFTP-Client\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding."
  desc  "fix", "Uninstall the \"TFTP Client\" feature.

    Start \"Server Manager\".
    Select the server with the feature.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"TFTP Client\" on the \"Features\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93389"
  tag rid: "SV-103475r1_rule"
  tag stig_id: "WN19-00-000370"
  tag fix_id: "F-99633r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe windows_feature('TFTP-Client') do
    it { should_not be_installed }
  end
end