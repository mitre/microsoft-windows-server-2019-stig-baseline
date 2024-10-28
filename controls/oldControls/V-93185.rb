# encoding: UTF-8

control "V-93185" do
  title "Windows Server 2019 must, at a minimum, off-load audit records of
interconnected systems in real time and off-load standalone systems weekly."
  desc  "Protection of log data includes assuring the log data is not
accidentally lost or deleted. Audit information stored in one location is
vulnerable to accidental or incidental deletion or alteration."
  desc  "rationale", ""
  desc  'check', "Verify the audit records, at a minimum, are off-loaded for interconnected
systems in real time and off-loaded for standalone systems weekly.

    If they are not, this is a finding."
  desc  'fix', "Configure the system to, at a minimum, off-load audit records
of interconnected systems in real time and off-load standalone systems weekly."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000479-GPOS-00224'
  tag 'gid': 'V-93185'
  tag 'rid': 'SV-103273r1_rule'
  tag 'stig_id': 'WN19-AU-000020'
  tag 'fix_id': 'F-99431r1_fix'
  tag 'cci': ["CCI-001851"]
  tag 'nist': ["AU-4 (1)", "Rev_4"]

  describe "A manual review is required to verify the operating system is, at a minimum, off-loading audit records of interconnected systems in real time and off-loading standalone systems weekly" do
    skip "A manual review is required to verify the operating system is, at a minimum, off-loading audit records of interconnected systems in real time and off-loading standalone systems weekly"
  end
end

