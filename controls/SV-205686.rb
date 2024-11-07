control 'SV-205686' do
  title 'Windows Server 2019 must prevent the display of slide shows on the lock screen.'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.'
  desc 'check', 'Verify the registry value below. 

If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen slide show" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-205686'
  tag rid: 'SV-205686r958478_rule'
  tag stig_id: 'WN19-CC-000010'
  tag fix_id: 'F-5951r354977_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization') do
    it { should have_property 'NoLockScreenSlideshow' }
    its('NoLockScreenSlideshow') { should cmp == 1 }
  end
end
