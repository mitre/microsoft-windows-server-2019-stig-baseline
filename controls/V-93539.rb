# encoding: UTF-8

control "V-93539" do
  title "Windows Server 2019 must restrict anonymous access to Named Pipes and Shares."
  desc  "Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in \"Network access: Named Pipes that can be accessed anonymously\" and \"Network access: Shares that can be accessed anonymously\", both of which must be blank under other requirements."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

    Value Name: RestrictNullSessAccess

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Network access: Restrict anonymous access to Named Pipes and Shares\" to \"Enabled\"."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000138-GPOS-00069"
  tag gid: "V-93539"
  tag rid: "SV-103625r1_rule"
  tag stig_id: "WN19-SO-000250"
  tag fix_id: "F-99783r1_fix"
  tag cci: ["CCI-001090"]
  tag nist: ["SC-4", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should have_property 'restrictnullsessaccess' }
    its('restrictnullsessaccess') { should cmp == 1 }
  end
end