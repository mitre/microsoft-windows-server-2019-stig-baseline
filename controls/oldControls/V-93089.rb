# encoding: UTF-8

control "V-93089" do
  title "Windows Server 2019 must be configured to audit Account Management -
Other Account Management Events successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Other Account Management Events records events such as the access of a
password hash or the Password Policy Checking API being called."
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

    If the system does not audit the following, this is a finding:

    Account Management >> Other Account Management Events - Success"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Account Management >> \"Audit Other Account Management
Events\" with \"Success\" selected."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000327-GPOS-00127'
  tag 'satisfies': ["SRG-OS-000327-GPOS-00127", "SRG-OS-000064-GPOS-00033",
"SRG-OS-000462-GPOS-00206", "SRG-OS-000466-GPOS-00210"]
  tag 'gid': 'V-93089'
  tag 'rid': 'SV-103177r1_rule'
  tag 'stig_id': 'WN19-AU-000090'
  tag 'fix_id': 'F-99335r1_fix'
  tag 'cci': ["CCI-000172", "CCI-002234"]
  tag 'nist': ["AU-12 c", "AC-6 (9)", "Rev_4"]

  describe.one do
    describe audit_policy do
      its('Other Account Management Events') { should eq 'Success' }
    end
    describe audit_policy do
      its('Other Account Management Events') { should eq 'Success and Failure' }
    end
  end
end

