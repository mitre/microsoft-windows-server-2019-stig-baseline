# encoding: UTF-8

control "V-93175" do
  title "Windows Server 2019 PowerShell script block logging must be enabled."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Enabling PowerShell script block logging will record detailed information
from the processing of PowerShell commands and scripts. This can provide
additional detail when malware has run on a system."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\

    Value Name: EnableScriptBlockLogging

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Windows PowerShell >> \"Turn
on PowerShell Script Block Logging\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000042-GPOS-00020'
  tag 'gid': 'V-93175'
  tag 'rid': 'SV-103263r1_rule'
  tag 'stig_id': 'WN19-CC-000460'
  tag 'fix_id': 'F-99421r1_fix'
  tag 'cci': ["CCI-000135"]
  tag 'nist': ["AU-3 (1)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    it { should have_property 'EnableScriptBlockLogging' }
    its('EnableScriptBlockLogging') { should cmp 1 }
  end
end

