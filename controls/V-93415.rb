# encoding: UTF-8

control "V-93415" do
  title "Windows Server 2019 must prevent Indexing of encrypted files."
  desc  "Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

    Value Name: AllowIndexingEncryptedStoresOrItems

    Value Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> \"Allow indexing of encrypted files\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93415"
  tag rid: "SV-103501r1_rule"
  tag stig_id: "WN19-CC-000410"
  tag fix_id: "F-99659r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should cmp 0 }
  end
end