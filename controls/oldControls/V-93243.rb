# encoding: UTF-8

control "V-93243" do
  title "Windows Server 2019 must be configured to enable Remote host allows
delegation of non-exportable credentials."
  desc  "An exportable version of credentials is provided to remote hosts when
using credential delegation which exposes them to theft on the remote host.
Restricted Admin mode or Remote Credential Guard allow delegation of
non-exportable credentials providing additional protection of the credentials.
Enabling this configures the host to support Restricted Admin mode or Remote
Credential Guard."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\

    Value Name: AllowProtectedCreds

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Credentials Delegation >> \"Remote host
allows delegation of non-exportable credentials\" to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93243'
  tag 'rid': 'SV-103331r1_rule'
  tag 'stig_id': 'WN19-CC-000100'
  tag 'fix_id': 'F-99489r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') do
    it { should have_property 'AllowProtectedCreds' }
    its('AllowProtectedCreds') { should cmp 1 }
  end
end

