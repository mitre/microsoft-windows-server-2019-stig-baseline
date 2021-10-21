

control 'V-93241' do
  title "Windows Server 2019 hardened Universal Naming Convention (UNC) paths
    must be defined to require mutual authentication and integrity for at least the
    \\\\*\\SYSVOL and \\\\*\\NETLOGON shares."
  desc "Additional security requirements are applied to UNC paths specified in
    hardened UNC paths before allowing access to them. This aids in preventing
    tampering with or spoofing of connections to these paths."
  desc  'rationale', ''
  desc  'check', "This requirement is applicable to domain-joined systems. For standalone
    systems, this is NA.

        If the following registry values do not exist or are not configured as
    specified, this is a finding:

        Registry Hive: HKEY_LOCAL_MACHINE
        Registry Path:
    \\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths\\

        Value Name: \\\\*\\NETLOGON
        Value Type: REG_SZ
        Value: RequireMutualAuthentication=1, RequireIntegrity=1

        Value Name: \\\\*\\SYSVOL
        Value Type: REG_SZ
        Value: RequireMutualAuthentication=1, RequireIntegrity=1

        Additional entries would not be a finding."
  desc 'fix', "Configure the policy value for Computer Configuration >> Administrative
    Templates >> Network >> Network Provider >> \"Hardened UNC Paths\" to
    \"Enabled\" with at least the following configured in \"Hardened UNC Paths\"
    (click the \"Show\" button to display):

        Value Name: \\\\*\\SYSVOL
        Value: RequireMutualAuthentication=1, RequireIntegrity=1

        Value Name: \\\\*\\NETLOGON
        Value: RequireMutualAuthentication=1, RequireIntegrity=1"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93241'
  tag 'rid': 'SV-103329r1_rule'
  tag 'stig_id': 'WN19-CC-000080'
  tag 'fix_id': 'F-99487r1_fix'
  tag 'cci': ['CCI-000366']
  tag 'nist': ['CM-6 b', 'Rev_4']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip
  keyvalue_netlogon = '\\\\*\\NETLOGON'
  keyvalue_sysvol = '\\\\*\\SYSVOL'

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
      it { should have_property keyvalue_sysvol }
      its(keyvalue_sysvol) { should cmp 'RequireMutualAuthentication=1, RequireIntegrity=1' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
      it { should have_property keyvalue_netlogon }
      its(keyvalue_netlogon) { should cmp 'RequireMutualAuthentication=1, RequireIntegrity=1' }
    end
  end
end
