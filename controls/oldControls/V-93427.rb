# encoding: UTF-8

control "V-93427" do
  title "Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection."
  desc  "This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

    Value Name: fPromptForPassword

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> \"Always prompt for password upon connection\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000373-GPOS-00157"
  tag satisfies: ["SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00156"]
  tag gid: "V-93427"
  tag rid: "SV-103513r1_rule"
  tag stig_id: "WN19-CC-000360"
  tag fix_id: "F-99671r1_fix"
  tag cci: ["CCI-002038"]
  tag nist: ["IA-11", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should cmp == 1 }
  end
end