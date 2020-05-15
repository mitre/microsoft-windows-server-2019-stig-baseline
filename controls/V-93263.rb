# encoding: UTF-8

control "V-93263" do
  title "Windows Server 2019 File Explorer shell protocol must run in protected
mode."
  desc  "The shell protocol will limit the set of folders that applications can
open when run in protected mode. Restricting files an application can open to a
limited set of folders increases the security of Windows."
  desc  "rationale", ""
  desc  'check', "The default behavior is for shell protected mode to be turned on for File
Explorer.

    If the registry value name below does not exist, this is not a finding.

    If it exists and is configured with a value of \"0\", this is not a finding.

    If it exists and is configured with a value of \"1\", this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

    Value Name: PreXPSP2ShellProtocolBehavior

    Value Type: REG_DWORD
    Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc  'fix', "The default behavior is for shell protected mode to be turned on for File
Explorer.

    If this needs to be corrected, configure the policy value for Computer
Configuration >> Administrative Templates >> Windows Components >> File
Explorer >> \"Turn off shell protocol protected mode\" to \"Not Configured\" or
\"Disabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93263'
  tag 'rid': 'SV-103351r1_rule'
  tag 'stig_id': 'WN19-CC-000330'
  tag 'fix_id': 'F-99509r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should_not have_property 'PreXPSP2ShellProtocolBehavior' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should have_property 'PreXPSP2ShellProtocolBehavior' }
      its('PreXPSP2ShellProtocolBehavior') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should have_property 'PreXPSP2ShellProtocolBehavior' }
      its('PreXPSP2ShellProtocolBehavior') { should cmp 0 }
    end
  end
end