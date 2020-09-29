# encoding: UTF-8

control "V-93279" do
  title "Windows Server 2019 must prevent local accounts with blank passwords from being used from the network."
  desc  "An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password does exist, enabling this setting will prevent network access, limiting the account to local console logon only."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

    Value Name: LimitBlankPasswordUse

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Accounts: Limit local account use of blank passwords to console logon only\" to \"Enabled\"."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93279"
  tag rid: "SV-103367r1_rule"
  tag stig_id: "WN19-SO-000020"
  tag fix_id: "F-99525r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa') do
    it { should have_property 'Limitblankpassworduse' }
    its('Limitblankpassworduse') { should cmp == 1 }
  end
end