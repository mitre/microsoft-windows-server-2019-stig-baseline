# encoding: UTF-8

control "V-93199" do
  title "Windows Server 2019 must prevent users from changing installation
options."
  desc  "Installation options for applications are typically controlled by
administrators. This setting prevents users from changing installation options
that may bypass security features."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

    Value Name: EnableUserControl

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Windows Installer >> \"Allow
user control over installs\" to \"Disabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000362-GPOS-00149'
  tag 'gid': 'V-93199'
  tag 'rid': 'SV-103287r1_rule'
  tag 'stig_id': 'WN19-CC-000420'
  tag 'fix_id': 'F-99445r1_fix'
  tag 'cci': ["CCI-001812"]
  tag 'nist': ["CM-11 (2)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    it { should have_property 'EnableUserControl' }
    its('EnableUserControl') { should cmp 0 }
  end
end

