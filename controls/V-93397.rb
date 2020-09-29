# encoding: UTF-8

control "V-93397" do
  title "Windows Server 2019 must not have Windows PowerShell 2.0 installed."
  desc  "Windows PowerShell 5.x added advanced logging features that can provide additional detail when malware has been run on a system. Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.x script block logging feature."
  desc  "rationale", ""
  desc  "check", "Open \"PowerShell\".
    Enter \"Get-WindowsFeature | Where Name -eq PowerShell-v2\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding."
  desc  "fix", "Uninstall the \"Windows PowerShell 2.0 Engine\".

    Start \"Server Manager\".
    Select the server with the feature.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"Windows PowerShell 2.0 Engine\" under \"Windows PowerShell\" on the \"Features\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93397"
  tag rid: "SV-103483r1_rule"
  tag stig_id: "WN19-00-000410"
  tag fix_id: "F-99641r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe windows_feature('PowerShell-v2') do
    it { should_not be_installed }
  end
end