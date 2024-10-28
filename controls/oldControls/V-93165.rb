# encoding: UTF-8

control "V-93165" do
  title "Windows Server 2019 must be configured to audit Object Access - Other
Object Access Events failures."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Auditing for other object access records events related to the management
of task scheduler jobs and COM+ objects."
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

    Object Access >> Other Object Access Events - Failure"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>
System Audit Policies >> Object Access >> \"Audit Other Object Access Events\"
with \"Failure\" selected."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000470-GPOS-00214'
  tag 'gid': 'V-93165'
  tag 'rid': 'SV-103253r1_rule'
  tag 'stig_id': 'WN19-AU-000230'
  tag 'fix_id': 'F-99411r1_fix'
  tag 'cci': ["CCI-000172"]
  tag 'nist': ["AU-12 c", "Rev_4"]

  describe.one do
    describe audit_policy do
      its('Other Object Access Events') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Other Object Access Events') { should eq 'Success and Failure' }
    end
  end
end

