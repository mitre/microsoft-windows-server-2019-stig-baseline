# encoding: UTF-8

control "V-93253" do
  title "Windows Server 2019 users must be prompted to authenticate when the
system wakes from sleep (on battery)."
  desc  "A system that does not require authentication when resuming from sleep
may provide access to unauthorized users. Authentication must always be
required when accessing a system. This setting ensures users are prompted for a
password when the system wakes from sleep (on battery)."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

    Value Name: DCSettingIndex

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Power Management >> Sleep Settings >>
\"Require a password when a computer wakes (on battery)\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93253'
  tag 'rid': 'SV-103341r1_rule'
  tag 'stig_id': 'WN19-CC-000180'
  tag 'fix_id': 'F-99499r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a Virtual Machine; This Control is NA.' do
      skip 'This is a Virtual Machine; This Control is NA.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
     it { should have_property 'DCSettingIndex' }
     its('DCSettingIndex') { should cmp 1 }
   end
  end
end

