control 'SV-205776' do
  title 'Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the operating system" or "Debug programs".'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN19-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

Privilege Use >> Sensitive Privilege Use - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Privilege Use >> "Audit Sensitive Privilege Use" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210']
  tag gid: 'V-205776'
  tag rid: 'SV-205776r958732_rule'
  tag stig_id: 'WN19-AU-000310'
  tag fix_id: 'F-6041r355247_fix'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']

  describe.one do
    describe audit_policy do
      its('Sensitive Privilege Use') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Sensitive Privilege Use') { should eq 'Success and Failure' }
    end
  end
end
