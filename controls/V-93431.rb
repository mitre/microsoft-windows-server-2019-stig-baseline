# encoding: UTF-8

control "V-93431" do
  title "Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled."
  desc  "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode."
  desc  "rationale", ""
  desc  "check", "UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).

    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: FilterAdministratorToken

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"User Account Control: Admin Approval Mode for the Built-in Administrator account\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000373-GPOS-00157"
  tag satisfies: ["SRG-OS-000373-GPOS-00157", "SRG-OS-000373-GPOS-00156"]
  tag gid: "V-93431"
  tag rid: "SV-103517r1_rule"
  tag stig_id: "WN19-SO-000380"
  tag fix_id: "F-99675r1_fix"
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
      it { should have_property 'FilterAdministratorToken' }
      its('FilterAdministratorToken') { should cmp == 1 }
    end
  end
end