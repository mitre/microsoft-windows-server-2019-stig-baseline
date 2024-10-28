# encoding: UTF-8

control "V-93303" do
  title "Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing."
  desc  "This setting controls the signing requirements for LDAP clients. This must be set to \"Negotiate signing\" or \"Require signing\", depending on the environment and type of LDAP server in use."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LDAP\\

    Value Name: LDAPClientIntegrity

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Network security: LDAP client signing requirements\" to \"Negotiate signing\" at a minimum."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93303"
  tag rid: "SV-103391r1_rule"
  tag stig_id: "WN19-SO-000320"
  tag fix_id: "F-99549r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP') do
    it { should have_property 'LDAPClientIntegrity' }
    its('LDAPClientIntegrity') { should cmp == 1 }
  end
end