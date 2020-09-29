# encoding: UTF-8

control "V-93501" do
  title "Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic."
  desc  "Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

    Value Name: AllowUnencryptedTraffic

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> \"Allow unencrypted traffic\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000393-GPOS-00173"
  tag satisfies: ["SRG-OS-000393-GPOS-00173", "SRG-OS-000394-GPOS-00174"]
  tag gid: "V-93501"
  tag rid: "SV-103587r1_rule"
  tag stig_id: "WN19-CC-000510"
  tag fix_id: "F-99745r1_fix"
  tag cci: ["CCI-002890", "CCI-003123"]
  tag nist: ["MA-4 (6)", "MA-4 (6)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end