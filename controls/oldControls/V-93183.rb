# encoding: UTF-8

control "V-93183" do
  title "Windows Server 2019 audit records must be backed up to a different
system or media than the system being audited."
  desc  "Protection of log data includes assuring the log data is not
accidentally lost or deleted. Audit information stored in one location is
vulnerable to accidental or incidental deletion or alteration."
  desc  "rationale", ""
  desc  'check', "Determine if a process to back up log data to a different system or media
than the system being audited has been implemented.

    If it has not, this is a finding."
  desc  'fix', "Establish and implement a process for backing up log data to
another system or media other than the system being audited."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000342-GPOS-00133'
  tag 'gid': 'V-93183'
  tag 'rid': 'SV-103271r1_rule'
  tag 'stig_id': 'WN19-AU-000010'
  tag 'fix_id': 'F-99429r1_fix'
  tag 'cci': ["CCI-001851"]
  tag 'nist': ["AU-4 (1)", "Rev_4"]

  describe 'A manual review is required to verify audit records are being backed up onto a different system or media than the system being audited' do
    skip 'A manual review is required to verify audit records are being backed up onto a different system or media than the system being audited'
  end
end

