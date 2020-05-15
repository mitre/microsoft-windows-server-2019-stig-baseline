# encoding: UTF-8

control "V-93203" do
  title "Windows Server 2019 system files must be monitored for unauthorized
changes."
  desc  "Monitoring system files for changes against a baseline on a regular
basis may help detect the possible introduction of malicious code on a system."
  desc  "rationale", ""
  desc  'check', "Determine whether the system is monitored for unauthorized changes to
system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline
on a weekly basis.

    If system files are not monitored for unauthorized changes, this is a
finding.

    A properly configured HBSS Policy Auditor 5.2 or later File Integrity
Monitor (FIM) module will meet the requirement for file integrity checking. The
Asset module within HBSS does not meet this requirement."
  desc  'fix', "Monitor the system for unauthorized changes to system files
(e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly
basis. This can be done with the use of various monitoring tools."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000363-GPOS-00150'
  tag 'gid': 'V-93203'
  tag 'rid': 'SV-103291r1_rule'
  tag 'stig_id': 'WN19-00-000220'
  tag 'fix_id': 'F-99449r1_fix'
  tag 'cci': ["CCI-001744"]
  tag 'nist': ["CM-3 (5)", "Rev_4"]

  describe 'A manual review is required to ensure system files are monitored for unauthorized changes' do
    skip 'A manual review is required to ensure system files are monitored for unauthorized changes'
  end
end

