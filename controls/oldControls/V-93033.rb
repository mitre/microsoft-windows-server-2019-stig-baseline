# encoding: UTF-8

control "V-93033" do
  title "Windows Server 2019 Active Directory Group Policy objects must have
proper access control permissions."
  desc  "When directory service database objects do not have appropriate access
control permissions, it may be possible for malicious users to create, read,
update, or delete the objects and degrade or destroy the integrity of the data.
When the directory service is used for identification, authentication, or
authorization functions, a compromise of the database objects could lead to a
compromise of all systems relying on the directory service.

    For Active Directory (AD), the Group Policy objects require special
attention. In a distributed administration model (i.e., help desk), Group
Policy objects are more likely to have access permissions changed from the
secure defaults. If inappropriate access permissions are defined for Group
Policy objects, this could allow an intruder to change the security policy
applied to all domain client computers (workstations and servers)."
  desc  "rationale", ""
  desc  'check', "This applies to domain controllers. It is NA for other systems.

    Review the permissions on Group Policy objects.

    Open \"Group Policy Management\" (available from various menus or run
\"gpmc.msc\").

    Navigate to \"Group Policy Objects\" in the domain being reviewed (Forest
>> Domains >> Domain).

    For each Group Policy object:

    Select the Group Policy object item in the left pane.

    Select the \"Delegation\" tab in the right pane.

    Select the \"Advanced\" button.

    Select each Group or user name.

    View the permissions.

    If any standard user accounts or groups have \"Allow\" permissions greater
than \"Read\" and \"Apply group policy\", this is a finding.

    Other access permissions that allow the objects to be updated are
considered findings unless specifically documented by the ISSO.

    The default permissions noted below satisfy this requirement.

    The permissions shown are at the summary level. More detailed permissions
can be viewed by selecting the next \"Advanced\" button, the desired Permission
entry, and the \"Edit\" button.

    Authenticated Users - Read, Apply group policy, Special permissions

    The special permissions for Authenticated Users are for Read-type
Properties. If detailed permissions include any Create, Delete, Modify, or
Write Permissions or Properties, this is a finding.

    The special permissions for the following default groups are not the focus
of this requirement and may include a wide range of permissions and properties:

    CREATOR OWNER - Special permissions
    SYSTEM - Read, Write, Create all child objects, Delete all child objects,
Special permissions
    Domain Admins - Read, Write, Create all child objects, Delete all child
objects, Special permissions
    Enterprise Admins - Read, Write, Create all child objects, Delete all child
objects, Special permissions
    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

    The Domain Admins and Enterprise Admins will not have the \"Delete all
child objects\" permission on the two default Group Policy objects: Default
Domain Policy and Default Domain Controllers Policy. They will have this
permission o'n organization created Group Policy objects."
  desc  'fix', "Maintain the permissions on Group Policy objects to not allow greater than
\"Read\" and \"Apply group policy\" for standard user accounts or groups. The
default permissions below meet this requirement:

    Authenticated Users - Read, Apply group policy, Special permissions

    The special permissions for Authenticated Users are for Read-type
Properties.

    CREATOR OWNER - Special permissions
    SYSTEM - Read, Write, Create all child objects, Delete all child objects,
Special permissions
    Domain Admins - Read, Write, Create all child objects, Delete all child
objects, Special permissions
    Enterprise Admins - Read, Write, Create all child objects, Delete all child
objects, Special permissions
    ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

    Document any other access permissions that allow the objects to be updated
with the ISSO.

    The Domain Admins and Enterprise Admins will not have the \"Delete all
child objects\" permission on the two default Group Policy objects: Default
Domain Policy and Default Domain Controllers Policy. They will have this
permission on created Group Policy objects."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93033'
  tag 'rid': 'SV-103121r1_rule'
  tag 'stig_id': 'WN19-DC-000090'
  tag 'fix_id': 'F-99279r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

  #Checked Code in 2016 and it is not a validate way of checking permissions, Until a command is put together that can get all GPO's in a Domain and then check all permissions, this is manually
  describe 'A manual review is required to ensure all Group Policies have the correct permisions' do
    skip 'A manual review is required to ensure all Group Policies have the correct permisions'
  end

end

