control 'SV-205843' do
  title 'Windows Server 2019 must, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  desc 'Protection of log data includes ensuring the log data is not accidentally lost or deleted. Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', 'Verify the audit records, at a minimum, are offloaded for interconnected systems in real time and offloaded for standalone or nondomain-joined systems weekly.

If they are not, this is a finding.'
  desc 'fix', 'Configure the system to, at a minimum, offload audit records of interconnected systems in real time and offload standalone or nondomain-joined systems weekly.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag gid: 'V-205843'
  tag rid: 'SV-205843r959008_rule'
  tag stig_id: 'WN19-AU-000020'
  tag fix_id: 'F-6108r916198_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  describe 'A manual review is required to verify the operating system is, at a minimum, off-loading audit records of interconnected systems in real time and off-loading standalone systems weekly' do
    skip 'A manual review is required to verify the operating system is, at a minimum, off-loading audit records of interconnected systems in real time and off-loading standalone systems weekly'
  end
end
