control 'SV-205792' do
  title 'Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Access records events related to users accessing an Active Directory object.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN19-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

DS Access >> Directory Service Access - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> DS Access >> "Directory Service Access" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag gid: 'V-205792'
  tag rid: 'SV-205792r958732_rule'
  tag stig_id: 'WN19-DC-000250'
  tag fix_id: 'F-6057r355739_fix'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
  describe.one do
   describe audit_policy do
    its('Directory Service Access') { should eq 'Failure' }
   end
   describe audit_policy do
    its('Directory Service Access') { should eq 'Success and Failure' }
   end
  end
 else
  describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
    skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
  end
 end
end
