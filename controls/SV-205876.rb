control 'SV-205876' do
  title 'Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords.'
  desc 'Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RefusePasswordChange

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Domain controller: Refuse machine account password changes" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205876'
  tag rid: 'SV-205876r991589_rule'
  tag stig_id: 'WN19-DC-000330'
  tag fix_id: 'F-6141r355991_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if ['4', '5'].include?(domain_role)
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
      it { should have_property 'RefusePasswordChange' }
      its('RefusePasswordChange') { should cmp 0 }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end
