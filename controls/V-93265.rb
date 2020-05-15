# encoding: UTF-8

control "V-93265" do
  title "Windows Server 2019 must prevent attachments from being downloaded
from RSS feeds."
  desc  "Attachments from RSS feeds may not be secure. This setting will
prevent attachments from being downloaded from RSS feeds."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

    Value Name: DisableEnclosureDownload

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> RSS Feeds >> \"Prevent
downloading of enclosures\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93265'
  tag 'rid': 'SV-103353r1_rule'
  tag 'stig_id': 'WN19-CC-000390'
  tag 'fix_id': 'F-99511r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    it { should have_property 'DisableEnclosureDownload' }
    its('DisableEnclosureDownload') { should cmp 1 }
  end
end

