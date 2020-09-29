# encoding: UTF-8

control "V-93215" do
  title "Windows Server 2019 must be maintained at a supported servicing level."
  desc  "Systems at unsupported servicing levels will not receive security
updates for new vulnerabilities, which leave them subject to exploitation.
Systems must be maintained at a servicing level supported by the vendor with
new security updates."
  desc  "rationale", ""
  desc  'check', "Open \"Command Prompt\".

    Enter \"winver.exe\".

    If the \"About Windows\" dialog box does not display \"Microsoft Windows
Server Version 1809 (Build 17763.xxx)\" or greater, this is a finding.

    Preview versions must not be used in a production environment."
  desc  'fix', "Update the system to a Version 1809 (Build 17763.xxx) or
greater."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93215'
  tag 'rid': 'SV-103303r1_rule'
  tag 'stig_id': 'WN19-00-000100'
  tag 'fix_id': 'F-99461r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  releaseid = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId
  current_build_number = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
  describe 'Microsoft Windows 2019 needs to be higher that release 1809' do
    subject { releaseid }
    it { should cmp >= 1809}
  end
  describe 'Microsoft Windows 2019 needs to be higher that build number 17763' do
    subject { current_build_number }
    it { should cmp >= 17763}
  end
end


