# encoding: UTF-8

control 'SV-205914' do
  title "Windows Server 2019 must not allow anonymous enumeration of Security
Account Manager (SAM) accounts."
  desc  "Anonymous enumeration of SAM accounts allows anonymous logon users
(null session connections) to list all accounts names, thus providing a list of
potential points to attack the system."
  desc  'rationale', ''
  desc  'check', "
    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

    Value Name: RestrictAnonymousSAM

    Value Type: REG_DWORD
    Value: 0x00000001 (1)
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Network access: Do not allow anonymous enumeration of SAM accounts\" to
\"Enabled\"."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205914'
  tag rid: 'SV-205914r569188_rule'
  tag stig_id: 'WN19-SO-000220'
  tag fix_id: 'F-6179r356105_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['V-93291', 'SV-103379']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'RestrictAnonymousSAM' }
    its('RestrictAnonymousSAM') { should cmp == 1 }
  end  

end

