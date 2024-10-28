# encoding: UTF-8

control "V-93173" do
  title "Windows Server 2019 command line data must be included in process
creation events."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks. Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Enabling \"Include command line data for process creation events\" will
record the command line information with the process creation events in the
log. This can provide additional detail when malware has run on a system."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\

    Value Name: ProcessCreationIncludeCmdLine_Enabled

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Audit Process Creation >> \"Include
command line in process creation events\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000042-GPOS-00020'
  tag 'gid': 'V-93173'
  tag 'rid': 'SV-103261r1_rule'
  tag 'stig_id': 'WN19-CC-000090'
  tag 'fix_id': 'F-99419r1_fix'
  tag 'cci': ["CCI-000135"]
  tag 'nist': ["AU-3 (1)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    it { should have_property 'ProcessCreationIncludeCmdLine_Enabled' }
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp 1 }
  end
end

