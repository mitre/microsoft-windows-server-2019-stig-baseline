# encoding: UTF-8

control "V-93505" do
  title "Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication."
  desc  "Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

    Value Name: AllowDigest

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> \"Disallow Digest authentication\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000125-GPOS-00065"
  tag gid: "V-93505"
  tag rid: "SV-103591r1_rule"
  tag stig_id: "WN19-CC-000490"
  tag fix_id: "F-99749r1_fix"
  tag cci: ["CCI-000877"]
  tag nist: ["MA-4 c", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp == 0 }
  end
end