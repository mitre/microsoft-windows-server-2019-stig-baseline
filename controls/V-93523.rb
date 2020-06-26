# encoding: UTF-8

control "V-93523" do
  title "Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop."
  desc  "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges."
  desc  "rationale", ""
  desc  "check", "UAC requirements are NA for Server Core installations (this is default installation option for Windows Server 2019 versus Server with Desktop Experience).
    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: ConsentPromptBehaviorAdmin

    Value Type: REG_DWORD
    Value: 0x00000002 (2) (Prompt for consent on the secure desktop)
    0x00000001 (1) (Prompt for credentials on the secure desktop)"
  desc  "fix", "
    Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode\" to \"Prompt for consent on the secure desktop\".

    The more secure option for this setting, \"Prompt for credentials on the secure desktop\", would also be acceptable."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000134-GPOS-00068"
  tag gid: "V-93523"
  tag rid: "SV-103609r1_rule"
  tag stig_id: "WN19-SO-000400"
  tag fix_id: "F-99767r1_fix"
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
      it { should have_property 'ConsentPromptBehaviorAdmin' }
      its('ConsentPromptBehaviorAdmin') { should be_between(1,2) }
    end
  end
end