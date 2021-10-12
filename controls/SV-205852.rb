# encoding: UTF-8

control 'SV-205852' do
  title "Windows Server 2019 must have software certificate installation files
removed."
  desc  "Use of software certificates and their accompanying installation files
for end users to access resources is less secure than the use of hardware-based
certificates."
  desc  'rationale', ''
  desc  'check', "
    Search all drives for *.p12 and *.pfx files.

    If any files with these extensions exist, this is a finding.

    This does not apply to server-based applications that have a requirement
for .p12 certificate files or Adobe PreFlight certificate files. Some
applications create files with extensions of .p12 that are not certificate
installation files. Removal of non-certificate installation files from systems
is not required. These must be documented with the ISSO.
  "
  desc  'fix', "
    Remove any certificate installation files (*.p12 and *.pfx) found on a
system.

    Note: This does not apply to server-based applications that have a
requirement for .p12 certificate files or Adobe PreFlight certificate files.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205852'
  tag rid: 'SV-205852r569188_rule'
  tag stig_id: 'WN19-00-000240'
  tag fix_id: 'F-6117r355919_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['V-93221', 'SV-103309']
  tag nist: ['CM-6 b']

  describe command('where /R c: *.p12 *.pfx') do
    its('stdout') { should eq '' }
  end

end

