# encoding: UTF-8

control "V-93261" do
  title "Windows Server 2019 Turning off File Explorer heap termination on
corruption must be disabled."
  desc  "Legacy plug-in applications may continue to function when a File
Explorer session has become corrupt. Disabling this feature will prevent this."
  desc  "rationale", ""
  desc  'check', "The default behavior is for File Explorer heap termination on corruption to
be enabled.

    If the registry Value Name below does not exist, this is not a finding.

    If it exists and is configured with a value of \"0\", this is not a finding.

    If it exists and is configured with a value of \"1\", this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

    Value Name: NoHeapTerminationOnCorruption

    Value Type: REG_DWORD
    Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc  'fix', "The default behavior is for File Explorer heap termination on corruption to
be disabled.

    If this needs to be corrected, configure the policy value for Computer
Configuration >> Administrative Templates >> Windows Components >> File
Explorer >> \"Turn off heap termination on corruption\" to \"Not Configured\"
or \"Disabled\"."
  impact 0.3
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93261'
  tag 'rid': 'SV-103349r1_rule'
  tag 'stig_id': 'WN19-CC-000320'
  tag 'fix_id': 'F-99507r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should_not have_property 'NoHeapTerminationOnCorruption' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should have_property 'NoHeapTerminationOnCorruption' }
      its('NoHeapTerminationOnCorruption') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should have_property 'NoHeapTerminationOnCorruption' }
      its('NoHeapTerminationOnCorruption') { should cmp 0 }
    end
  end
end

