control 'SV-205747' do
  title 'Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.'
  desc "The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials."
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems. It is NA for domain controllers.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)'
  desc 'fix', 'Navigate to the policy Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict clients allowed to make remote calls to SAM".

Select "Edit Security" to configure the "Security descriptor:".

Add "Administrators" in "Group or user names:" if it is not already listed (this is the default).

Select "Administrators" in "Group or user names:".

Select "Allow" for "Remote Access" in "Permissions for "Administrators".

Click "OK".

The "Security descriptor:" must be populated with "O:BAG:BAD:(A;;RC;;;BA) for the policy to be enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-205747'
  tag rid: 'SV-205747r958726_rule'
  tag stig_id: 'WN19-MS-000060'
  tag fix_id: 'F-6012r857328_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if ['4', '5'].include?(domain_role)
    impact 0.0
    describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers' do
      skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
      it { should have_property 'RestrictRemoteSAM' }
      its('RestrictRemoteSAM') { should cmp 'O:BAG:BAD:(A;;RC;;;BA)' }
    end
  end
end
