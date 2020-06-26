# encoding: UTF-8

control "V-93411" do
  title "Windows Server 2019 Windows Defender SmartScreen must be enabled."
  desc  "Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen can block potentially malicious programs or warn users."
  desc  "rationale", ""
  desc  "check", "This is applicable to unclassified systems; for other systems, this is NA.

    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

    Value Name: EnableSmartScreen

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> \"Configure Windows Defender SmartScreen\" to \"Enabled\" with either option \"Warn\" or \"Warn and prevent bypass\" selected.
    Windows 2019 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Explorer."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93411"
  tag rid: "SV-103497r2_rule"
  tag stig_id: "WN19-CC-000300"
  tag fix_id: "F-99655r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  if input('sensitive_system') == true || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
      it { should have_property 'EnableSmartScreen' }
      its('EnableSmartScreen') { should cmp 1 }
    end
  end
end