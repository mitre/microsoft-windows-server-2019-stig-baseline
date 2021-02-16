# encoding: UTF-8

control "V-93013" do
  title "Windows Server 2019 Deny log on as a service user right on
domain-joined member servers must be configured to prevent access from highly
privileged domain accounts. No other groups or accounts must be assigned this
right."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on as a service\" user right defines accounts that are
denied logon as a service.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower-trust systems helps mitigate the risk of
privilege escalation from credential theft attacks, which could lead to the
compromise of an entire domain.

    Incorrect configurations could prevent services from starting and result in
a denial of service."
  desc  "rationale", ""
  desc  'check', "This applies to member servers and standalone systems. A separate version
applies to domain controllers.

    Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If the following accounts or groups are not defined for the \"Deny log on
as a service\" user right on domain-joined systems, this is a finding:

    - Enterprise Admins Group
    - Domain Admins Group

    If any accounts or groups are defined for the \"Deny log on as a service\"
user right on non-domain-joined systems, this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If the following SIDs are not defined for the \"SeDenyServiceLogonRight\"
user right on domain-joined systems, this is a finding:

    S-1-5-root domain-519 (Enterprise Admins)
    S-1-5-domain-512 (Domain Admins)

    If any SIDs are defined for the user right on non-domain-joined systems,
this is a finding."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log
on as a service\" to include the following:

    Domain systems:
    - Enterprise Admins Group
    - Domain Admins Group"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-93013'
  tag 'rid': 'SV-103101r1_rule'
  tag 'stig_id': 'WN19-MS-000100'
  tag 'fix_id': 'F-99259r1_fix'
  tag 'cci': ["CCI-000213"]
  tag 'nist': ["AC-3", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  case domain_role
  when '4', '5'
    impact 0.0
    desc 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control'
    describe 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control' do
      skip 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control'
    end
  when '3'
    domain_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Domain Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

    domain_admin_sid = json(command: domain_query).params
    enterprise_admin_query = <<-EOH
              $group = New-Object System.Security.Principal.NTAccount('Enterprise Admins')
              $sid = ($group.Translate([security.principal.securityidentifier])).value
              $sid | ConvertTo-Json
              EOH

    enterprise_admin_sid = json(command: enterprise_admin_query).params
    describe security_policy do
      its('SeDenyServiceLogonRight') { should include "#{domain_admin_sid}" }
    end
    describe security_policy do
      its('SeDenyServiceLogonRight') { should include "#{enterprise_admin_sid}" }
    end
  when '2'
    describe security_policy do
      its('SeDenyServiceLogonRight') { should be_empty }
    end
  end
end
