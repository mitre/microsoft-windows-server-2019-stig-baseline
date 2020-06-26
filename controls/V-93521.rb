# encoding: UTF-8

control "V-93521" do
  title "Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."
  desc  "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts."
  desc  "rationale", ""
  desc  "check", "UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2019 versus Server with Desktop Experience).
    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: EnableUIADesktopToggle

    Value Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000134-GPOS-00068"
  tag gid: "V-93521"
  tag rid: "SV-103607r1_rule"
  tag stig_id: "WN19-SO-000390"
  tag fix_id: "F-99765r1_fix"
  tag cci: ["CCI-001084"]
  tag nist: ["SC-3", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'EnableUIADesktopToggle' }
      its('EnableUIADesktopToggle') { should cmp == 0 }
    end
  end
end