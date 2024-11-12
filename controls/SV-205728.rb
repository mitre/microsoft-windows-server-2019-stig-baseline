control 'SV-205728' do
  title 'Windows Server 2019 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where Endpoint Security Solution (ESS) is used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws. The operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools.'
  desc 'check', "Verify DOD-approved ESS software is installed and properly operating. Ask the site information system security manager (ISSM) for documentation of the ESS software installation and configuration.

If the ISSM is not able to provide a documented configuration for an installed ESS or if the ESS software is not properly maintained or used, this is a finding.

Note: Example of documentation can be a copy of the site's CCB approved Software Baseline with version of software noted or a memo from the ISSM stating current ESS software and version."
  desc 'fix', 'Install a DOD-approved ESS software and ensure it is operating continuously.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag gid: 'V-205728'
  tag rid: 'SV-205728r1000127_rule'
  tag stig_id: 'WN19-00-000290'
  tag fix_id: 'F-5993r997840_fix'
  tag cci: ['CCI-001233', 'CCI-000366']
  tag nist: ['SI-2 (2)', 'CM-6 b']

  org_name = input('org_name')

  describe "A manual review is required to verify #{org_name[:acronym]} approved HBSS software is installed, configured, and properly operating. Ask the operator to document the HBSS software installation and configuration. If the operator is not able to provide a documented configuration for an installed HBSS or if the HBSS software is not properly configured maintained, or used, this is a finding." do
    skip "A manual review is required to verify #{org_name[:acronym]} approved HBSS software is installed, configured, and properly operating. Ask the operator to document the HBSS software installation and configuration. If the operator is not able to provide a documented configuration for an installed HBSS or if the HBSS software is not properly configured maintained, or used, this is a finding."
  end
end
