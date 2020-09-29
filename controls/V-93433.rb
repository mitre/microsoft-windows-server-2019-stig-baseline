# encoding: UTF-8

control "V-93433" do
  title "Windows Server 2019 User Account Control must automatically deny standard user requests for elevation."
  desc  "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account."
  desc  "rationale", ""
  desc  "check", "UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).

    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: ConsentPromptBehaviorUser

    Value Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"User Account Control: Behavior of the elevation prompt for standard users\" to \"Automatically deny elevation requests\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000373-GPOS-00157"
  tag satisfies: ["SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00156"]
  tag gid: "V-93433"
  tag rid: "SV-103519r1_rule"
  tag stig_id: "WN19-SO-000410"
  tag fix_id: "F-99677r1_fix"
  tag cci: ["CCI-002038"]
  tag nist: ["IA-11", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'ConsentPromptBehaviorUser' }
      its('ConsentPromptBehaviorUser') { should cmp == 0 }
    end
  end
end