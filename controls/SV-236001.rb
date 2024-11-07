control 'SV-236001' do
  title 'The Windows Explorer Preview pane must be disabled for Windows Server 2019.'
  desc 'A known vulnerability in Windows could allow the execution of malicious code by either opening a compromised document or viewing it in the Windows Preview pane.

Organizations must disable the Windows Preview pane and Windows Detail pane.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Value Name: NoPreviewPane

Value Type: REG_DWORD

Value: 1

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

Value Name: NoReadingPane

Value Type: REG_DWORD

Value: 1'
  desc 'fix', 'Ensure the following settings are configured for Windows Server 2019 locally or applied through group policy.
 
Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn off Preview Pane" to "Enabled".

Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane "Turn on or off details pane" to "Enabled" and "Configure details pane" to "Always hide".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-39220r641819_chk'
  tag severity: 'medium'
  tag gid: 'V-236001'
  tag rid: 'SV-236001r958478_rule'
  tag stig_id: 'WN19-CC-000451'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-39183r641820_fix'
  tag 'documentable'
  tag legacy: ['V-102625', 'SV-111575']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
