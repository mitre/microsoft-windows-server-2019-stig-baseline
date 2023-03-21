control 'SV-205742' do
  title 'Windows Server 2019 Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions.'
  desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

    Review the permissions on the Domain Controllers OU.
    Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").
    Select "Advanced Features" in the "View" menu if not previously selected.
    Select the "Domain Controllers" OU (folder in folder icon).
    Right-click and select "Properties".
    Select the "Security" tab.
    If the permissions on the Domain Controllers OU do not restrict changes to System, Domain Admins, Enterprise Admins and Administrators, this is a finding.

    The default permissions listed below satisfy this requirement.
    Domains supporting Microsoft Exchange will have additional Exchange related permissions on the Domain Controllers OU.  These may include some change related permissions and are not a finding.
    The permissions shown are at the summary level. More detailed permissions can be viewed by selecting the "Advanced" button, the desired Permission entry, and the "View" or "Edit" button.
    Except where noted otherwise, the special permissions may include a wide range of permissions and properties and are acceptable for this requirement.

    CREATOR OWNER - Special permissions
    SELF - Special permissions
    Authenticated Users - Read, Special permissions
    The special permissions for Authenticated Users are Read types.
    If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.

    SYSTEM - Full Control
    Domain Admins - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions
    Enterprise Admins - Full Control
    Key Admins - Special permissions
    Enterprise Key Admins - Special permissions
    Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions
    Pre-Windows 2000 Compatible Access - Special permissions
    The Special permissions for Pre-Windows 2000 Compatible Access are Read types.

    If detailed permissions include any Create, Delete, Modify, or Write Permissions or Properties, this is a finding.
    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions'
  desc 'fix', 'Limit the permissions on the Domain Controllers OU to restrict changes to System, Domain Admins, Enterprise Admins and Administrators.
    The default permissions listed below satisfy this requirement.
    Domains supporting Microsoft Exchange will have additional Exchange related permissions on the Domain Controllers OU.  These may include some change related permissions.

    CREATOR OWNER - Special permissions
    SELF - Special permissions
    Authenticated Users - Read, Special permissions
    The special permissions for Authenticated Users are Read types.
    SYSTEM - Full Control
    Domain Admins - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions
    Enterprise Admins - Full Control
    Key Admins - Special permissions
    Enterprise Key Admins - Special permissions
    Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions
    Pre-Windows 2000 Compatible Access - Special permissions
    The special permissions for Pre-Windows 2000 Compatible Access are Read types.
    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-93035'
  tag rid: 'SV-103123r1_rule'
  tag stig_id: 'WN19-DC-000100'
  tag fix_id: 'F-99281r1_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)', 'Rev_4']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    perm_query = <<-EOH
                    import-module ActiveDirectory
                    Set-Location ad:
                    $distinguishedName = (Get-ADDomain).DistinguishedName
                    $acl_rules = (Get-Acl "OU=Domain Controllers,$distinguishedName").Access
                    $acl_rules | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json
                    EOH

    acl_rules = json(command: perm_query).params
    netbiosname = json(command: 'Get-ADDomain | Select NetBIOSName | ConvertTo-JSON').params['NetBIOSName']

    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' }
          its(['ActiveDirectoryRights']) { should cmp 'GenericRead' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\Authenticated Users' }
          its(['ActiveDirectoryRights']) { should cmp 'GenericRead' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\SYSTEM' }
          its(['ActiveDirectoryRights']) { should cmp 'GenericAll' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\SYSTEM' }
          its(['ActiveDirectoryRights']) { should cmp 'GenericAll' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp "#{netbiosname}\\Domain Admins" }
          its(['ActiveDirectoryRights']) { should cmp 'CreateChild, Self, WriteProperty, ExtendedRight, GenericRead, WriteDacl, WriteOwner' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'BUILTIN\\Pre-Windows 2000 Compatible Access' }
          its(['ActiveDirectoryRights']) { should cmp 'ReadProperty' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\SELF' }
          its(['ActiveDirectoryRights']) { should cmp 'ReadProperty, WriteProperty' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'NT AUTHORITY\\SELF' }
          its(['ActiveDirectoryRights']) { should cmp 'ReadProperty, WriteProperty, ExtendedRight' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp "#{netbiosname}\\Enterprise Admins" }
          its(['ActiveDirectoryRights']) { should cmp 'GenericAll' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'BUILTIN\\Pre-Windows 2000 Compatible Access' }
          its(['ActiveDirectoryRights']) { should cmp 'ListChildren' }
        end
      end
    end
    describe.one do
      acl_rules.each do |acl_rule|
        describe "Audit rule property for principal: #{acl_rule['IdentityReference']}" do
          subject { acl_rule }
          its(['IdentityReference']) { should cmp 'BUILTIN\\Administrators' }
          its(['ActiveDirectoryRights']) { should cmp 'CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner' }
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
