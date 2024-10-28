# encoding: UTF-8

control "V-93151" do
  title "Windows Server 2019 must force audit policy subcategory settings to
override audit policy category settings."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.
    This setting allows administrators to enable more precise auditing
capabilities."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

    Value Name: SCENoApplyLegacyAuditPolicy

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000062-GPOS-00031'
  tag 'gid': 'V-93151'
  tag 'rid': 'SV-103239r1_rule'
  tag 'stig_id': 'WN19-SO-000050'
  tag 'fix_id': 'F-99397r1_fix'
  tag 'cci': ["CCI-000169"]
  tag 'nist': ["AU-12 a", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
   it { should have_property 'SCENoApplyLegacyAuditPolicy' }
   its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end 
end