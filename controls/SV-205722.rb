# encoding: UTF-8

control 'SV-205722' do
  title "Windows Server 2019 Remote Desktop Services must prevent drive
redirection."
  desc  "Preventing users from sharing the local drives on their client
computers with Remote Session Hosts that they access helps reduce possible
exposure of sensitive data."
  desc  'rationale', ''
  desc  'check', "
    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal
Services\\

    Value Name: fDisableCdm

    Type: REG_DWORD
    Value: 0x00000001 (1)
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Remote Desktop Services >>
Remote Desktop Session Host >> Device and Resource Redirection >> \"Do not
allow drive redirection\" to \"Enabled\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-205722'
  tag rid: 'SV-205722r569188_rule'
  tag stig_id: 'WN19-CC-000350'
  tag fix_id: 'F-5987r355085_fix'
  tag cci: ['CCI-001090']
  tag legacy: ['SV-103619', 'V-93533']
  tag nist: ['SC-4']

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp == 1 }
  end

end

