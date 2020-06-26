# encoding: UTF-8

control "V-93517" do
  title "Windows Server 2019 administrator accounts must not be enumerated during elevation."
  desc  "Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

    Value Name: EnumerateAdministrators

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> \"Enumerate administrator accounts on elevation\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000134-GPOS-00068"
  tag gid: "V-93517"
  tag rid: "SV-103603r1_rule"
  tag stig_id: "WN19-CC-000240"
  tag fix_id: "F-99761r1_fix"
  tag cci: ["CCI-001084"]
  tag nist: ["SC-3", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp == 0 }
  end
end