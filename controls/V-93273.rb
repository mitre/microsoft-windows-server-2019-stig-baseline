# encoding: UTF-8

control "V-93273" do
  title "Windows Server 2019 domain controllers must be configured to allow
reset of machine account passwords."
  desc  "Enabling this setting on all domain controllers in a domain prevents
domain members from changing their computer account passwords. If these
passwords are weak or compromised, the inability to change them may leave these
computers vulnerable."
  desc  "rationale", ""
  desc  "check", "
    This applies to domain controllers. It is NA for other systems.

    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

    Value Name: RefusePasswordChange

    Value Type: REG_DWORD
    Value: 0x00000000 (0)
  "
  desc  "fix", "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Domain controller: Refuse machine account password changes\" to \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93273"
  tag rid: "SV-103361r1_rule"
  tag stig_id: "WN19-DC-000330"
  tag fix_id: "F-99519r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]
end

