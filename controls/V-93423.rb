# encoding: UTF-8

control "V-93423" do
  title "Windows Server 2019 must not have the Telnet Client installed."
  desc  "Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system."
  desc  "rationale", ""
  desc  "check", "Open \"PowerShell\".

    Enter \"Get-WindowsFeature | Where Name -eq Telnet-Client\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding."
  desc  "fix", "Uninstall the \"Telnet Client\" feature.

    Start \"Server Manager\".
    Select the server with the feature.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"Telnet Client\" on the \"Features\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000096-GPOS-00050"
  tag gid: "V-93423"
  tag rid: "SV-103509r1_rule"
  tag stig_id: "WN19-00-000360"
  tag fix_id: "F-99667r1_fix"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b", "Rev_4"]

  describe windows_feature('Telnet-Client') do
    it { should_not be_installed }
  end
end