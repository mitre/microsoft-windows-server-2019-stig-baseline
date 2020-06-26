# encoding: UTF-8

control "V-93407" do
  title "Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen."
  desc  "Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows."
  desc  "rationale", ""
  desc  "check", "Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

    Value Name: DontDisplayNetworkSelectionUI

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> \"Do not display network selection UI\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93407"
  tag rid: "SV-103493r1_rule"
  tag stig_id: "WN19-CC-000170"
  tag fix_id: "F-99651r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should cmp == 1 }
  end
end