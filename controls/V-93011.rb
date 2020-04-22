# encoding: UTF-8

control "V-93011" do
  title "Windows Server 2019 Deny log on as a batch job user right on
domain-joined member servers must be configured to prevent access from highly
privileged domain accounts and from unauthenticated access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny log on as a batch job\" user right defines accounts that are
prevented from logging on to the system as a batch job, such as Task Scheduler.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
Domain Admins groups on lower-trust systems helps mitigate the risk of
privilege escalation from credential theft attacks, which could lead to the
compromise of an entire domain.

    The Guests group must be assigned to prevent unauthenticated access.
  "
  desc  "rationale", ""
  desc  "check", "
    This applies to member servers and standalone systems. A separate version
applies to domain controllers.

    Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If the following accounts or groups are not defined for the \"Deny log on
as a batch job\" user right, this is a finding:

    Domain Systems Only:
    - Enterprise Admins Group
    - Domain Admins Group

    All Systems:
    - Guests Group

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If the following SIDs are not defined for the \"SeDenyBatchLogonRight\"
user right, this is a finding.

    Domain Systems Only:
    S-1-5-root domain-519 (Enterprise Admins)
    S-1-5-domain-512 (Domain Admins)

    All Systems:
    S-1-5-32-546 (Guests)
  "
  desc  "fix", "
    Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Deny log
on as a batch job\" to include the following:

    Domain Systems Only:
    - Enterprise Admins Group
    - Domain Admins Group

    All Systems:
    - Guests Group
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000080-GPOS-00048"
  tag gid: "V-93011"
  tag rid: "SV-103099r1_rule"
  tag stig_id: "WN19-MS-000090"
  tag fix_id: "F-99257r1_fix"
  tag cci: ["CCI-000213"]
  tag nist: ["AC-3", "Rev_4"]
end

