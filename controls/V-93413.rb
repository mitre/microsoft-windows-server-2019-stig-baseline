# encoding: UTF-8

control "V-93413" do
  title "Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP."
  desc  "Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential."
  desc  "rationale", ""
  desc  "check", "The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

    If the registry value name below does not exist, this is not a finding.
    If it exists and is configured with a value of \"0\", this is not a finding.
    If it exists and is configured with a value of \"1\", this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

    Value Name: AllowBasicAuthInClear

    Value Type: REG_DWORD
    Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc  "fix", "The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.
    If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> \"Turn on Basic feed authentication over HTTP\" to \"Not Configured\" or \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93413"
  tag rid: "SV-103499r1_rule"
  tag stig_id: "WN19-CC-000400"
  tag fix_id: "F-99657r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds').has_property?('AllowBasicAuthInClear')
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    its('AllowBasicAuthInClear') { should cmp 0 }
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
      it { should_not have_property 'AllowBasicAuthInClear' }
    end
  end
end