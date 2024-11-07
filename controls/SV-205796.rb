control 'SV-205796' do
  title 'Windows Server 2019 Application event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application\\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-205796'
  tag rid: 'SV-205796r958752_rule'
  tag stig_id: 'WN19-CC-000270'
  tag fix_id: 'F-6061r355751_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end
