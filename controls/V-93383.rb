# encoding: UTF-8

control "V-93383" do
  title "Windows Server 2019 must not have the Fax Server role installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system."
  desc  "rationale", ""
  desc  "check", "Open \"PowerShell\".

    Enter \"Get-WindowsFeature | Where Name -eq Fax\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding."
  desc  "fix", "Uninstall the \"Fax Server\" role.

    Start \"Server Manager\".
    Select the server with the role.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"Fax Server\" on the \"Roles\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93383"
  tag rid: "SV-103469r1_rule"
  tag stig_id: "WN19-00-000320"
  tag fix_id: "F-99627r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe windows_feature('fax') do
    it { should_not be_installed }
  end
end