# encoding: UTF-8

control "V-93519" do
  title "Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."
  desc  "A compromised local administrator account can provide means for an attacker to move laterally between domain systems.
    With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network."
  desc  "rationale", ""
  desc  "check", "This applies to member servers. For domain controllers and standalone systems, this is NA.
    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive:  HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

    Value Name:  LocalAccountTokenFilterPolicy

    Type:  REG_DWORD
    Value: 0x00000000 (0)

    This setting may cause issues with some network scanning tools if local administrative accounts are used remotely. Scans should use domain accounts where possible. If a local administrative account must be used, temporarily enabling the privileged token by configuring the registry value to \"1\" may be required."
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> \"Apply UAC restrictions to local accounts on network logons\" to \"Enabled\".
    This policy setting requires the installation of the SecGuide custom templates included with the STIG package. \"SecGuide.admx\" and \" SecGuide.adml\" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000134-GPOS-00068"
  tag gid: "V-93519"
  tag rid: "SV-103605r1_rule"
  tag stig_id: "WN19-MS-000020"
  tag fix_id: "F-99763r1_fix"
  tag cci: ["CCI-001084"]
  tag nist: ["SC-3", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '3'
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'LocalAccountTokenFilterPolicy' }
      its('LocalAccountTokenFilterPolicy') { should cmp == 0 }
    end
  else
    impact 0.0
    describe 'This requirement is only applicable to member servers' do
      skip 'This control is NA as the requirement is only applicable to member servers'
    end
  end
end