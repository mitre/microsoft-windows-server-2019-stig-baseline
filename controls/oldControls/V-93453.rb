# encoding: UTF-8

control "V-93453" do
  title "Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems."
  desc  "Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections."
  desc  "rationale", ""
  desc  "check", "This applies to member servers and standalone systems, it is NA for domain controllers.

    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive:  HKEY_LOCAL_MACHINE
    Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

    Value Name:  RestrictRemoteClients

    Type:  REG_DWORD
    Value:  0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Procedure Call >> \"Restrict Unauthenticated RPC clients\" to \"Enabled\" with \"Authenticated\" selected."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000379-GPOS-00164"
  tag gid: "V-93453"
  tag rid: "SV-103539r1_rule"
  tag stig_id: "WN19-MS-000040"
  tag fix_id: "F-99697r1_fix"
  tag cci: ["CCI-001967"]
  tag nist: ["IA-3 (1)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc') do
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should cmp == 1 }
  end
end