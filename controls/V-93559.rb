control 'SV-205827' do
  title 'Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

    Value Name: RequireSecuritySignature

    Value Type: REG_DWORD
    Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft network server: Digitally sign communications (always)" to "Enabled".'
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-93559'
  tag rid: 'SV-103645r1_rule'
  tag stig_id: 'WN19-SO-000190'
  tag fix_id: 'F-99803r1_fix'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)', 'Rev_4']

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should cmp == 1 }
  end
end
