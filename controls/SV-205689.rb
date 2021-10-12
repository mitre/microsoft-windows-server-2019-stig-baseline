# encoding: UTF-8

control 'SV-205689' do
  title 'Windows Server 2019 printing over HTTP must be turned off.'
  desc  "Some features may communicate with the vendor, sending system
information or downloading data or components for the feature. Turning off this
capability will prevent potentially sensitive information from being sent
outside the enterprise and will prevent uncontrolled updates to the system.

    This setting prevents the client computer from printing over HTTP, which
allows the computer to print to printers on the intranet as well as the
Internet.
  "
  desc  'rationale', ''
  desc  'check', "
    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

    Value Name: DisableHTTPPrinting

    Type: REG_DWORD
    Value: 0x00000001 (1)
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Internet Communication Management >>
Internet Communication settings >> \"Turn off printing over HTTP\" to
\"Enabled\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-205689'
  tag rid: 'SV-205689r569188_rule'
  tag stig_id: 'WN19-CC-000160'
  tag fix_id: 'F-5954r354986_fix'
  tag cci: ['CCI-000381']
  tag legacy: ['SV-103491', 'V-93405']
  tag nist: ['CM-7 a']

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should cmp == 1 }
  end

end

