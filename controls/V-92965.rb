# encoding: UTF-8

control "V-92965" do
  title "Windows Server 2019 Deny log on through Remote Desktop Services user
right on domain-joined member servers must be configured to prevent access from
highly privileged domain accounts and all local accounts and from
unauthenticated access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on through Remote Desktop Services\" user right defines the
accounts that are prevented from logging on using Remote Desktop Services.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower-trust systems helps mitigate the risk of
privilege escalation from credential theft attacks, which could lead to the
compromise of an entire domain.

    Local accounts on domain-joined systems must also be assigned this right to
decrease the risk of lateral movement resulting from credential theft attacks.

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
through Remote Desktop Services\" user right, this is a finding:

    Domain Systems Only:
    - Enterprise Admins group
    - Domain Admins group
    - Local account (see Note below)

    All Systems:
    - Guests group

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If the following SIDs are not defined for the
\"SeDenyRemoteInteractiveLogonRight\" user right, this is a finding.

    Domain Systems Only:
    S-1-5-root domain-519 (Enterprise Admins)
    S-1-5-domain-512 (Domain Admins)
    S-1-5-113 (\"Local account\")

    All Systems:
    S-1-5-32-546 (Guests)

    Note: \"Local account\" is referring to the Windows built-in security group."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log
on through Remote Desktop Services\" to include the following:

    Domain Systems Only:
    - Enterprise Admins group
    - Domain Admins group
    - Local account (see Note below)

    All Systems:
    - Guests group

    Note: \"Local account\" is referring to the Windows built-in security group."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000297-GPOS-00115'
  tag 'gid': 'V-92965'
  tag 'rid': 'SV-103053r1_rule'
  tag 'stig_id': 'WN19-MS-000120'
  tag 'fix_id': 'F-99211r1_fix'
  tag 'cci': ["CCI-002314"]
  tag 'nist': ["AC-17 (1)", "Rev_4"]

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
      its('SeDenyRemoteInteractiveLogonRight') { should include "#{domain_admin_sid}" }
    end
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "#{enterprise_admin_sid}" }
    end
    describe.one do
      describe security_policy do
          its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-5-113" }
      end
      describe security_policy do
          its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-5-114" }
      end
    end
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include 'S-1-5-32-546' }
    end
  when '2'
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
    end
  end
end