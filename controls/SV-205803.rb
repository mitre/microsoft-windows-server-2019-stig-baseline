control 'SV-205803' do
  title 'Windows Server 2019 system files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

If system files are not monitored for unauthorized changes, this is a finding.

An approved and properly configured solution will contain both a list of baselines that includes all system file locations and a file comparison task that is scheduled to run at least weekly.'
  desc 'fix', 'Monitor the system for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis. This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag gid: 'V-205803'
  tag rid: 'SV-205803r958794_rule'
  tag stig_id: 'WN19-00-000220'
  tag fix_id: 'F-6068r355772_fix'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']

  describe 'A manual review is required to ensure system files are monitored for unauthorized changes' do
    skip 'A manual review is required to ensure system files are monitored for unauthorized changes'
  end
end
