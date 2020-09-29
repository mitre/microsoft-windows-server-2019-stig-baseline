# encoding: UTF-8

control "V-93299" do
  title "Windows Server 2019 must prevent PKU2U authentication using online identities."
  desc  "PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

    Value Name: AllowOnlineID

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Network security: Allow PKU2U authentication requests to this computer to use online identities\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93299"
  tag rid: "SV-103387r1_rule"
  tag stig_id: "WN19-SO-000280"
  tag fix_id: "F-99545r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u') do
    it { should have_property 'AllowOnlineID' }
    its('AllowOnlineID') { should cmp == 0 }
  end
end