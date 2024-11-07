control 'SV-257503' do
  title 'Windows Server 2019 must have PowerShell Transcription enabled.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell Transcription will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription\\

Value Name: EnableTranscripting

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Transcription" to "Enabled".

Specify the Transcript output directory to point to a Central Log Server or another secure location to prevent user access.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-61238r921893_chk'
  tag severity: 'medium'
  tag gid: 'V-257503'
  tag rid: 'SV-257503r958420_rule'
  tag stig_id: 'WN19-CC-000530'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-61162r921894_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']

  # registry_key takes a path argument with the hive appended to the beginning
  # REG_DWORD is a 32bit unsigned integer
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    it { should exist }
    it { should have_property 'EnableTranscripting' }
    its('EnableTranscripting') { should cmp 1 }
  end


end
