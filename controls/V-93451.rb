# encoding: UTF-8

control "V-93451" do
  title "Windows Server 2019 computer clock synchronization tolerance must be limited to five minutes or less."
  desc  "This setting determines the maximum time difference (in minutes) that Kerberos will tolerate between the time on a client's clock and the time on a server's clock while still considering the two clocks synchronous. In order to prevent replay attacks, Kerberos uses timestamps as part of its protocol definition. For timestamps to work properly, the clocks of the client and the server need to be in sync as much as possible."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.
    Verify the following is configured in the Default Domain Policy:

    Open \"Group Policy Management\".
    Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest >> Domains >> Domain).
    Right-click on the \"Default Domain Policy\".
    Select \"Edit\".
    Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

    If the \"Maximum tolerance for computer clock synchronization\" is greater than \"5\" minutes, this is a finding."
  desc  "fix", "Configure the policy value in the Default Domain Policy for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> \"Maximum tolerance for computer clock synchronization\" to a maximum of \"5\" minutes or less."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000112-GPOS-00057"
  tag satisfies: ["SRG-OS-000112-GPOS-00057", "SRG-OS-000113-GPOS-00058"]
  tag gid: "V-93451"
  tag rid: "SV-103537r1_rule"
  tag stig_id: "WN19-DC-000060"
  tag fix_id: "F-99695r1_fix"
  tag cci: ["CCI-001941", "CCI-001942"]
  tag nist: ["IA-2 (8)", "IA-2 (9)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('MaxClockSkew') { should be <= 5 }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end