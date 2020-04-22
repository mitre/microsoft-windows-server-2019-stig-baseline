# encoding: UTF-8

control "V-93043" do
  title "Windows Server 2019 must only allow administrators responsible for the
member server or standalone system to have Administrator rights on the system."
  desc  "An account that does not have Administrator duties must not have
Administrator rights. Such rights would allow the account to bypass or modify
required security restrictions on that machine and make it vulnerable to attack.

    System administrators must log on to systems using only accounts with the
minimum level of authority necessary.

    For domain-joined member servers, the Domain Admins group must be replaced
by a domain member server administrator group (see V-36433 in the Active
Directory Domain STIG). Restricting highly privileged accounts from the local
Administrators group helps mitigate the risk of privilege escalation resulting
from credential theft attacks.

    Standard user accounts must not be members of the built-in Administrators
group.
  "
  desc  "rationale", ""
  desc  "check", "
    This applies to member servers and standalone systems. A separate version
applies to domain controllers.

    Open \"Computer Management\".

    Navigate to \"Groups\" under \"Local Users and Groups\".

    Review the local \"Administrators\" group.

    Only administrator groups or accounts responsible for administration of the
system may be members of the group.

    For domain-joined member servers, the Domain Admins group must be replaced
by a domain member server administrator group.

    Standard user accounts must not be members of the local Administrator group.

    If accounts that do not have responsibility for administration of the
system are members of the local Administrators group, this is a finding.

    If the built-in Administrator account or other required administrative
accounts are found on the system, this is not a finding.
  "
  desc  "fix", "
    Configure the local \"Administrators\" group to include only administrator
groups or accounts responsible for administration of the system.

    For domain-joined member servers, replace the Domain Admins group with a
domain member server administrator group.

    Remove any standard user accounts.
  "
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000324-GPOS-00125"
  tag gid: "V-93043"
  tag rid: "SV-103131r1_rule"
  tag stig_id: "WN19-MS-000010"
  tag fix_id: "F-99289r1_fix"
  tag cci: ["CCI-002235"]
  tag nist: ["AC-6 (10)", "Rev_4"]
end

