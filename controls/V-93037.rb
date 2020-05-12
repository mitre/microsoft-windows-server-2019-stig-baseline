# encoding: UTF-8

control "V-93037" do
  title "Windows Server 2019 organization created Active Directory
Organizational Unit (OU) objects must have proper access control permissions."
  desc  "When directory service database objects do not have appropriate access
control permissions, it may be possible for malicious users to create, read,
update, or delete the objects and degrade or destroy the integrity of the data.
When the directory service is used for identification, authentication, or
authorization functions, a compromise of the database objects could lead to a
compromise of all systems that rely on the directory service.

    For Active Directory, the OU objects require special attention. In a
distributed administration model (i.e., help desk), OU objects are more likely
to have access permissions changed from the secure defaults. If inappropriate
access permissions are defined for OU objects, it could allow an intruder to
add or delete users in the OU. This could result in unauthorized access to data
or a denial of service (DoS) to authorized users."
  desc  "rationale", ""
  desc  'check', "This applies to domain controllers. It is NA for other systems.

    Review the permissions on domain-defined OUs.

    Open \"Active Directory Users and Computers\" (available from various menus
or run \"dsa.msc\").

    Ensure \"Advanced Features\" is selected in the \"View\" menu.

    For each OU that is defined (folder in folder icon) excluding the Domain
Controllers OU:

    Right-click the OU and select \"Properties\".

    Select the \"Security\" tab.

    If the Allow type permissions on the OU are not at least as restrictive as
those below, this is a finding.

    The permissions shown are at the summary level. More detailed permissions
can be viewed by selecting the \"Advanced\" button, the desired Permission
entry, and the \"Edit\" or \"View\" button.

    Except where noted otherwise, the special permissions may include a wide
range of permissions and properties and are acceptable for this requirement.

    CREATOR OWNER - Special permissions

    Self - Special permissions

    Authenticated Users - Read, Special permissions

    The Special permissions for Authenticated Users are Read type. If detailed
permissions include any Create, Delete, Modify, or Write Permissions or
Properties, this is a finding.

    SYSTEM - Full Control

    Domain Admins - Full Control

    Enterprise Admins - Full Control

    Key Admins - Special permissions

    Enterprise Key Admins - Special permissions

    Administrators - Read, Write, Create all child objects, Generate resultant
set of policy (logging), Generate resultant set of policy (planning), Special
permissions

    Pre-Windows 2000 Compatible Access - Special permissions

    The Special permissions for Pre-Windows 2000 Compatible Access are for Read
types. If detailed permissions include any Create, Delete, Modify, or Write
Permissions or Properties, this is a finding.

    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

    If an ISSO-approved distributed administration model (help desk or other
user support staff) is implemented, permissions above Read may be allowed for
groups documented by the ISSO.

    If any OU with improper permissions includes identification or
authentication data (e.g., accounts, passwords, or password hash data) used by
systems to determine access control, the severity is CAT I (e.g., OUs that
include user accounts, including service/application accounts).

    If an OU with improper permissions does not include identification and
authentication data used by systems to determine access control, the severity
is CAT II (e.g., Workstation, Printer OUs)."
  desc  'fix', "Maintain the Allow type permissions on domain-defined OUs to be at least as
restrictive as the defaults below.

    Document any additional permissions above Read with the ISSO if an approved
distributed administration model (help desk or other user support staff) is
implemented.

    CREATOR OWNER - Special permissions

    Self - Special permissions

    Authenticated Users - Read, Special permissions

    The special permissions for Authenticated Users are Read type.

    SYSTEM - Full Control

    Domain Admins - Full Control

    Enterprise Admins - Full Control

    Key Admins - Special permissions

    Enterprise Key Admins - Special permissions

    Administrators - Read, Write, Create all child objects, Generate resultant
set of policy (logging), Generate resultant set of policy (planning), Special
permissions

    Pre-Windows 2000 Compatible Access - Special permissions

    The special permissions for Pre-Windows 2000 Compatible Access are for Read
types.

    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions"
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93037'
  tag 'rid': 'SV-103125r1_rule'
  tag 'stig_id': 'WN19-DC-000110'
  tag 'fix_id': 'F-99283r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
    if domain_role == '4' || domain_role == '5'
       distinguishedName = json(command: '(Get-ADDomain).DistinguishedName | ConvertTo-Json').params
       ou_list = json(command: "Get-ADOrganizationalUnit -filter * -SearchBase '#{distinguishedName}' | Select-Object -ExpandProperty distinguishedname | ConvertTo-Json").params
       exclude_dc = json(command: "Get-ADOrganizationalUnit -filter * -SearchBase '#{distinguishedName}'  | Where-Object {$_.distinguishedname -like 'OU=Domain Controllers,#{distinguishedName}'} |  Select-Object -ExpandProperty distinguishedname | ConvertTo-Json").params
       ou_list.delete(exclude_dc)
       netbiosname = json(command: 'Get-ADDomain | Select NetBIOSName | ConvertTo-JSON').params['NetBIOSName']
      ou_list.each do |ou|
         acl_rules = json(command: "(Get-ACL -Audit -Path AD:'#{ou}').Access | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS" }
             its(['ActiveDirectoryRights']) { should cmp "GenericRead"}
            end
           end
         end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "NT AUTHORITY\\Authenticated Users" }
             its(['ActiveDirectoryRights']) { should cmp "GenericRead"}
            end
           end
         end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
             its(['ActiveDirectoryRights']) { should cmp "GenericAll"}
            end
           end
         end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
             its(['ActiveDirectoryRights']) { should cmp "CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner"}
            end
           end
          end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "BUILTIN\\Pre-Windows 2000 Compatible Access" }
             its(['ActiveDirectoryRights']) { should cmp "ListChildren"}
            end
           end
          end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "#{netbiosname}\\Domain Admins" }
             its(['ActiveDirectoryRights']) { should cmp "GenericAll"}
            end
           end
         end
          describe.one do
           acl_rules.each do |acl_rule|
            describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
             subject { acl_rule }
             its(['IdentityReference']) { should cmp "#{netbiosname}\\Enterprise Admins" }
             its(['ActiveDirectoryRights']) { should cmp "GenericAll"}
            end
           end
          end
        describe.one do
          acl_rules.each do |acl_rule|
          describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SELF" }
            its(['ActiveDirectoryRights']) { should cmp "ReadProperty, WriteProperty, ExtendedRight"}
          end
        end
      end
        describe.one do
         acl_rules.each do |acl_rule|
          describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SELF" }
            its(['ActiveDirectoryRights']) { should cmp "ReadProperty, WriteProperty"}
          end
         end
       end
        describe.one do
         acl_rules.each do |acl_rule|
          describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SELF" }
            its(['ActiveDirectoryRights']) { should cmp "WriteProperty"}
          end
         end
        end
        describe.one do
         acl_rules.each do |acl_rule|
          describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SELF" }
            its(['ActiveDirectoryRights']) { should cmp "Self"}
          end
         end
        end
      end
    else
      impact 0.0
      desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
      describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
       skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
     end
    end
end

