# encoding: UTF-8

control "V-93311" do
  title "Windows Server 2019 must preserve zone information when saving attachments."
  desc  "Attachments from outside sources may contain malicious code. Preserving zone of origin (Internet, intranet, local, restricted) information on file attachments allows Windows to determine risk."
  desc  "rationale", ""
  desc  "check", "The default behavior is for Windows to mark file attachments with their zone information.

    If the registry Value Name below does not exist, this is not a finding.
    If it exists and is configured with a value of \"2\", this is not a finding.
    If it exists and is configured with a value of \"1\", this is a finding.

    Registry Hive: HKEY_CURRENT_USER
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

    Value Name: SaveZoneInformation

    Value Type: REG_DWORD
    Value: 0x00000002 (2) (or if the Value Name does not exist)"
  desc  "fix", "The default behavior is for Windows to mark file attachments with their zone information.

    If this needs to be corrected, configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> Attachment Manager >> \"Do not preserve zone information in file attachments\" to \"Not Configured\" or \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93311"
  tag rid: "SV-103399r1_rule"
  tag stig_id: "WN19-UC-000010"
  tag fix_id: "F-99557r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  if registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments').has_property?('SaveZoneInformation')
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
    its('SaveZoneInformation') { should cmp 2 }
    end
  else
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
      it { should_not have_property 'SaveZoneInformation' }
    end
  end
end