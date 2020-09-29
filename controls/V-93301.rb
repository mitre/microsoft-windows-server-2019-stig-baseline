# encoding: UTF-8

control "V-93301" do
  title "Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."
  desc  "The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to standalone computers that are running later versions."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

    Value Name: LmCompatibilityLevel

    Value Type: REG_DWORD
    Value: 0x00000005 (5)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Network security: LAN Manager authentication level\" to \"Send NTLMv2 response only. Refuse LM & NTLM\"."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93301"
  tag rid: "SV-103389r1_rule"
  tag stig_id: "WN19-SO-000310"
  tag fix_id: "F-99547r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    it { should have_property 'LmCompatibilityLevel' }
    its('LmCompatibilityLevel') { should cmp == 5 }
  end
end