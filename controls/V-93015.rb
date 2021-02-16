# encoding: UTF-8

control "V-93015" do
  title "Windows Server 2019 Deny log on locally user right on domain-joined
member servers must be configured to prevent access from highly privileged
domain accounts and from unauthenticated access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on locally\" user right defines accounts that are prevented
from logging on interactively.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower-trust systems helps mitigate the risk of
privilege escalation from credential theft attacks, which could lead to the
compromise of an entire domain.

    The Guests group must be assigned this right to prevent unauthenticated
access."
  desc  "rationale", ""
  desc  'check', "This applies to member servers and standalone systems. A separate version
applies to domain controllers.

    Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If the following accounts or groups are not defined for the \"Deny log on
locally\" user right, this is a finding:

    Domain Systems Only:
    - Enterprise Admins Group
    - Domain Admins Group

    All Systems:
    - Guests Group

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If the following SIDs are not defined for the
\"SeDenyInteractiveLogonRight\" user right, this is a finding:

    Domain Systems Only:
    S-1-5-root domain-519 (Enterprise Admins)
    S-1-5-domain-512 (Domain Admins)

    All Systems:
    S-1-5-32-546 (Guests)"
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log
on locally\" to include the following:

    Domain Systems Only:
    - Enterprise Admins Group
    - Domain Admins Group

    All Systems:
    - Guests Group"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-93015'
  tag 'rid': 'SV-103103r1_rule'
  tag 'stig_id': 'WN19-MS-000110'
  tag 'fix_id': 'F-99261r1_fix'
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
  when '2'
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
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
      its('SeDenyInteractiveLogonRight') { should include "#{domain_admin_sid}" }
    end
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include "#{enterprise_admin_sid}" }
    end
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
    end
  end
end
