# encoding: UTF-8

control "V-93391" do
  title "Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed."
  desc  "SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks and is not FIPS compliant."
  desc  "rationale", ""
  desc  "check", "Different methods are available to disable SMBv1 on Windows Server 2019. This is the preferred method, however if WN19-00-000390 and WN19-00-000400 are configured, this is NA.

    Open \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Get-WindowsFeature -Name FS-SMB1\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding."
  desc  "fix", "Uninstall the SMBv1 protocol.

    Open \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Uninstall-WindowsFeature -Name FS-SMB1 -Restart\".
    (Omit the Restart parameter if an immediate restart of the system cannot be done.)

    Alternately:
    Start \"Server Manager\".
    Select the server with the feature.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"SMB 1.0/CIFS File Sharing Support\" on the \"Features\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93391"
  tag rid: "SV-103477r1_rule"
  tag stig_id: "WN19-00-000380"
  tag fix_id: "F-99635r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  if powershell("Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1").stdout.strip == "0" && powershell("Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' -Name Start").stdout.strip == "4"
    impact 0.0
    describe 'Controls V-93393 and V-93395 configuration successful' do
      skip 'This is NA as the successful configuration of Controls V-93393 (STIG ID# WN19-00-000390) and V-93395 (STIG ID# WN19-00-000400) meets the requirement'
    end
  else
    state = powershell("Get-WindowsFeature -Name FS-SMB1 | Select -ExpandProperty 'InstallState'").stdout.strip
    describe "Server Message Block (SMB) v1 protocol msut not be installed" do
      subject { state }
      it { should_not eq "Installed" }
    end
  end
end