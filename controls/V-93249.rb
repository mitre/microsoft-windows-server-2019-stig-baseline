control 'V-205865' do
  title 'Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.'
  desc 'Compromised boot drivers can introduce malware prior to protection mechanisms that load after initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application. At a minimum, drivers determined to be bad must not be allowed.'
  desc 'check', 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy to enforce "Good, unknown and bad but critical" (preventing "bad").

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0x00000007 (7)", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch\\

Value Name: DriverLoadPolicy

Value Type: REG_DWORD
Value: 0x00000001 (1), 0x00000003 (3), or 0x00000008 (8) (or if the Value Name does not exist)

Possible values for this setting are:
8 - Good only
1 - Good and unknown
3 - Good, unknown and bad but critical
7 - All (which includes "bad" and would be a finding)'
  desc 'fix', 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy to enforce "Good, unknown and bad but critical" (preventing "bad").

If this needs to be corrected or a more secure setting is desired, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Early Launch Antimalware >> "Boot-Start Driver Initialization Policy" to "Not Configured" or "Enabled" with any option other than "All" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205865'
  tag rid: 'SV-205865r991589_rule'
  tag stig_id: 'WN19-CC-000130'
  tag fix_id: 'F-6130r355958_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch') do
      it { should_not have_property 'DriverLoadPolicy' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch') do
      it { should have_property 'DriverLoadPolicy' }
      its('DriverLoadPolicy') { should be_in [1, 3, 8] }
    end
  end
end
