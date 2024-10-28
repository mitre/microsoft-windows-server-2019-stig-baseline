# encoding: UTF-8

control "V-93099" do
  title "Windows Server 2019 must be configured to audit Policy Change -
Authorization Policy Change successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Authorization Policy Change records events related to changes in user
rights, such as \"Create a token object\"."
  desc  "rationale", ""
  desc  'check', "Security Option \"Audit: Force audit policy subcategory settings (Windows
Vista or later) to override audit policy category settings\" must be set to
\"Enabled\" (WN19-SO-000050) for the detailed auditing subcategories to be
effective.

    Use the \"AuditPol\" tool to review the current Audit Policy configuration:

    Open \"PowerShell\" or a \"Command Prompt\" with elevated privileges (\"Run
as administrator\").

    Enter \"AuditPol /get /category:*\"

    Compare the \"AuditPol\" settings with the following:

    If the system does not audit the following, this is a finding.

    Policy Change >> Authorization Policy Change - Success"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Policy Change >> \"Audit Authorization Policy Change\"
with \"Success\" selected."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000327-GPOS-00127'
  tag 'satisfies': ["SRG-OS-000327-GPOS-00127", "SRG-OS-000064-GPOS-00033",
"SRG-OS-000462-GPOS-00206", "SRG-OS-000466-GPOS-00210"]
  tag 'gid': 'V-93099'
  tag 'rid': 'SV-103187r1_rule'
  tag 'stig_id': 'WN19-AU-000290'
  tag 'fix_id': 'F-99345r1_fix'
  tag 'cci': ["CCI-000172", "CCI-002234"]
  tag 'nist': ["AU-12 c", "AC-6 (9)", "Rev_4"]

  describe.one do
    describe audit_policy do
      its('Authentication Policy Change') { should eq 'Success' }
    end
    describe audit_policy do
      its('Authentication Policy Change') { should eq 'Success and Failure' }
    end
  end
end

