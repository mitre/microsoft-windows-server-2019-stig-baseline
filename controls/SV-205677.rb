control 'SV-205677' do
  title 'Windows Server 2019 must have the roles and features required by the system documented.'
  desc 'Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.'
  desc 'check', 'Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".'
  desc 'fix', 'Document the roles and features required for the system to operate. Uninstall any that are not required.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-205677'
  tag rid: 'SV-205677r958478_rule'
  tag stig_id: 'WN19-00-000270'
  tag fix_id: 'F-5942r354950_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'A manual review is required to verify that the roles and features required by the system are documented' do
    skip 'A manual review is required to verify that the roles and features required by the system are documented'
  end
end
