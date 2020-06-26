# encoding: UTF-8

control "V-93545" do
  title "Windows Server 2019 domain controllers must require LDAP access signing."
  desc  "Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. The risk of an attacker pulling this off can be decreased by implementing strong physical security measures to protect the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.
    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\

    Value Name: LDAPServerIntegrity

    Value Type: REG_DWORD
    Value: 0x00000002 (2)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain controller: LDAP server signing requirements\" to \"Require signing\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000423-GPOS-00187"
  tag satisfies: ["SRG-OS-000423-GPOS-00187", "SRG-OS-000424-GPOS-00188"]
  tag gid: "V-93545"
  tag rid: "SV-103631r1_rule"
  tag stig_id: "WN19-DC-000320"
  tag fix_id: "F-99789r1_fix"
  tag cci: ["CCI-002418", "CCI-002421"]
  tag nist: ["SC-8", "SC-8 (1)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters') do
      it { should have_property 'LDAPServerIntegrity' }
      its('LDAPServerIntegrity') { should cmp 2 }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end