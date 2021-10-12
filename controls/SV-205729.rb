# encoding: UTF-8

control 'SV-205729' do
  title "Windows Server 2019 must be configured to audit Logon/Logoff - Account
Lockout successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Account Lockout events can be used to identify potentially malicious logon
attempts."
  desc  'rationale', ''
  desc  'check', "
    Security Option \"Audit: Force audit policy subcategory settings (Windows
Vista or later) to override audit policy category settings\" must be set to
\"Enabled\" (WN19-SO-000050) for the detailed auditing subcategories to be
effective.

    Use the \"AuditPol\" tool to review the current Audit Policy configuration:

    Open \"PowerShell\" or a \"Command Prompt\" with elevated privileges (\"Run
as administrator\").

    Enter \"AuditPol /get /category:*\"

    Compare the \"AuditPol\" settings with the following:

    If the system does not audit the following, this is a finding.

    Logon/Logoff >> Account Lockout - Success
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Logon/Logoff >> \"Audit Account Lockout\" with
\"Success\" selected."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag satisfies: ['SRG-OS-000240-GPOS-00090', 'SRG-OS-000470-GPOS-00214']
  tag gid: 'V-205729'
  tag rid: 'SV-205729r569188_rule'
  tag stig_id: 'WN19-AU-000150'
  tag fix_id: 'F-5994r355106_fix'
  tag cci: ['CCI-001404', 'CCI-000172']
  tag legacy: ['SV-103075', 'V-92987']
  tag nist: ['AC-2 (4)', 'AU-12 c']

  describe.one do
    describe audit_policy do
      its('Account Lockout') { should eq 'Success' }
    end
    describe audit_policy do
      its('Account Lockout') { should eq 'Success and Failure' }
    end
  end

end

