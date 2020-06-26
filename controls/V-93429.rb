# encoding: UTF-8

control "V-93429" do
  title "Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials."
  desc  "Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

    Value Name: DisableRunAs

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> \"Disallow WinRM from storing RunAs credentials\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000373-GPOS-00157"
  tag satisfies: ["SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00156"]
  tag gid: "V-93429"
  tag rid: "SV-103515r1_rule"
  tag stig_id: "WN19-CC-000520"
  tag fix_id: "F-99673r1_fix"
  tag cci: ["CCI-002038"]
  tag nist: ["IA-11", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should cmp == 1 }
  end
end