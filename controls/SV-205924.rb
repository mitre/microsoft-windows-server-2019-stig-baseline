control 'SV-205924' do
  title 'Windows Server 2019 must preserve zone information when saving attachments.'
  desc 'Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  desc 'check', 'The default behavior is for Windows to mark file attachments with their zone information.

If the registry Value Name below does not exist, this is not a finding.

If it exists and is configured with a value of "2", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

Value Name: SaveZoneInformation

Value Type: REG_DWORD
Value: 0x00000002 (2) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Windows to mark file attachments with their zone information.

If this needs to be corrected, configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Attachment Manager >> "Do not preserve zone information in file attachments" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205924'
  tag rid: 'SV-205924r991589_rule'
  tag stig_id: 'WN19-UC-000010'
  tag fix_id: 'F-6189r356135_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
      it { should_not have_property 'SaveZoneInformation' }
    end
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
      it { should have_property 'SaveZoneInformation' }
      its('SaveZoneInformation') { should_not cmp 1 }
      its('SaveZoneInformation') { should cmp 2 }
    end
  end
end
