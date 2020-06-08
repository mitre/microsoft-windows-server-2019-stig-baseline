# encoding: UTF-8

control "V-93419" do
  title "Windows Server 2019 local users on domain-joined member servers must not be enumerated."
  desc  "The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel."
  desc  "rationale", ""
  desc  "check", "This applies to member servers. For domain controllers and standalone systems, this is NA.

    If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

    Value Name: EnumerateLocalUsers

    Type: REG_DWORD
    Value: 0x00000000 (0)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> \"Enumerate local users on domain-joined computers\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93419"
  tag rid: "SV-103505r1_rule"
  tag stig_id: "WN19-MS-000030"
  tag fix_id: "F-99663r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  # SK: Copied from Windows 2016 V-73533
  # SK: Test - passed for Domain controller
  # QJ: Member server test pending | Member server should return 3 for the domain_role command, but since the condition is met but other installations, it might not be accruate

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if !(domain_role == '4') && !(domain_role == '5')
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System') do
      it { should have_property 'EnumerateLocalUsers' }
      its('EnumerateLocalUsers') { should cmp 0 }
    end
  else
    impact 0.0
    describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems' do
      skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    end
  end
  
end