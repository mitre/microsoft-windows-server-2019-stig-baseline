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

  # SK: Copied from Windows 2016 V-73299
  # Q: Condition to add -  if WN19-00-000390 and WN19-00-000400 are configured, this is NA.
  # Q: Test pending

  if registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters').has_property_value?('SMB1', :dword, 0) && registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10').has_property_value?('Start', :dword, 4)
    impact 0.0
    desc 'This control is not applicable, as controls V-78123 and V-78125 are configured'
  else
    describe windows_feature('FS-SMB1') do
      it { should_not be_installed }
    end
  end

  # SK: Copied from Windows 2012 V-73805

  if os['release'].to_f < 6.3
    impact 0.0
    describe 'System is not Windows 2012, control is NA' do
      skip 'System is not Windows 2012, control is NA'
    end
  else
   state = powershell("(Get-WindowsOptionalFeature -Online | Where {$_.FeatureName -eq 'SMB1Protocol'}).State ").stdout.strip
   describe 'SMB 1.0 Procotocl is disabled as part of Security Requirement' do
    subject { state }
    it { should_not eq "Enabled"}
   end
  end
end