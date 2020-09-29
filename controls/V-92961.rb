# encoding: UTF-8

control "V-92961" do
  title "Windows Server 2019 machine inactivity limit must be set to 15 minutes
or less, locking the system with the screen saver."
  desc  "Unattended systems are susceptible to unauthorized use and should be
locked when unattended. The screen saver should be set at a maximum of 15
minutes and be password protected. This protects critical and sensitive data
from exposure to unauthorized personnel with physical access to the computer."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: InactivityTimeoutSecs

    Value Type: REG_DWORD
    Value: 0x00000384 (900) (or less, excluding \"0\" which is effectively
disabled)"
  desc 'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Interactive logon: Machine inactivity limit\" to \"900\" seconds or less,
excluding \"0\" which is effectively disabled."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000028-GPOS-00009'
  tag 'satisfies': ["SRG-OS-000028-GPOS-00009", "SRG-OS-000029-GPOS-00010",
"SRG-OS-000031-GPOS-00012"]
  tag 'gid': 'V-92961'
  tag 'rid': 'SV-103049r1_rule'
  tag 'stig_id': 'WN19-SO-000120'
  tag 'fix_id': 'F-99207r1_fix'
  tag 'cci': ["CCI-000056", "CCI-000057", "CCI-000060"]
  tag 'nist': ["AC-11 b", "AC-11 a", "AC-11 (1)", "Rev_4"]

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      its('InactivityTimeoutSecs') { should be <= 900 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      its('InactivityTimeoutSecs') { should eq 0 }
    end
  end
end

