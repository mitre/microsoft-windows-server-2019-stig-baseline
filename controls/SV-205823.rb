# encoding: UTF-8

control 'SV-205823' do
  title "Windows Server 2019 setting Domain member: Digitally sign secure
channel data (when possible) must be configured to Enabled."
  desc  "Requests sent on the secure channel are authenticated, and sensitive
information (such as passwords) is encrypted, but the channel is not integrity
checked. If this policy is enabled, outgoing secure channel traffic will be
signed."
  desc  'rationale', ''
  desc  'check', "
    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

    Value Name: SignSecureChannel

    Value Type: REG_DWORD
    Value: 0x00000001 (1)
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Domain member: Digitally sign secure channel data (when possible)\" to
\"Enabled\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-205823'
  tag rid: 'SV-205823r569188_rule'
  tag stig_id: 'WN19-SO-000080'
  tag fix_id: 'F-6088r355832_fix'
  tag cci: ['CCI-002421', 'CCI-002418']
  tag legacy: ['V-93551', 'SV-103637']
  tag nist: ['SC-8 (1)', 'SC-8']

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'SignSecureChannel' }
    its('SignSecureChannel') { should cmp == 1 }
  end

end

