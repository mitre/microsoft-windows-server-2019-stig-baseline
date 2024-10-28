# encoding: UTF-8

control "V-93269" do
  title "Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart."
  desc  "Windows can be configured to automatically sign the user back in after a Windows Update restart. Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart."
  desc  "rationale", ""
  desc  "check", "Verify the registry value below. If it does not exist or is not configured as specified, this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: DisableAutomaticRestartSignOn

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> \"Sign-in last interactive user automatically after a system-initiated restart\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00229"
  tag gid: "V-93269"
  tag rid: "SV-103357r1_rule"
  tag stig_id: "WN19-CC-000450"
  tag fix_id: "F-99515r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'DisableAutomaticRestartSignOn' }
    its('DisableAutomaticRestartSignOn') { should cmp 1 }
  end
end