# encoding: UTF-8

control "V-93027" do
  title "Windows Server 2019 must only allow administrators responsible for the
domain controller to have Administrator rights on the system."
  desc  "An account that does not have Administrator duties must not have
Administrator rights. Such rights would allow the account to bypass or modify
required security restrictions on that machine and make it vulnerable to attack.

    System administrators must log on to systems using only accounts with the
minimum level of authority necessary.

    Standard user accounts must not be members of the built-in Administrators
group."
  desc  "rationale", ""
  desc  'check', "This applies to domain controllers. A separate version applies to other
systems.

    Review the Administrators group. Only the appropriate administrator groups
or accounts responsible for administration of the system may be members of the
group.

    Standard user accounts must not be members of the local administrator group.

    If prohibited accounts are members of the local administrators group, this
is a finding.

    If the built-in Administrator account or other required administrative
accounts are found on the system, this is not a finding."
  desc  'fix', "
    Configure the Administrators group to include only administrator groups or
accounts that are responsible for the system.

    Remove any standard user accounts."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93027'
  tag 'rid': 'SV-103115r1_rule'
  tag 'stig_id': 'WN19-DC-000010'
  tag 'fix_id': 'F-99273r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

 domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
  administrators = input('local_administrators_dc')
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split("\r\n")
    if administrator_group.empty?
        impact 0.0
        describe 'There are no users with administrative privileges' do
         skip 'This control is not applicable'
        end
    else
     administrator_group.each do |user|
      describe user.to_s do
       it { should be_in administrators }
      end
     end
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end