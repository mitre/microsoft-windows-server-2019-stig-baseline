# encoding: UTF-8

control 'SV-205703' do
  title "Windows Server 2019 Kerberos service ticket maximum lifetime must be
limited to 600 minutes or less."
  desc  "This setting determines the maximum amount of time (in minutes) that a
granted session ticket can be used to access a particular service. Session
tickets are used only to authenticate new connections with servers. Ongoing
operations are not interrupted if the session ticket used to authenticate the
connection expires during the connection."
  desc  'rationale', ''
  desc  'check', "
    This applies to domain controllers. It is NA for other systems.

    Verify the following is configured in the Default Domain Policy:

    Open \"Group Policy Management\".

    Navigate to \"Group Policy Objects\" in the Domain being reviewed (Forest
>> Domains >> Domain).

    Right-click on the \"Default Domain Policy\".

    Select \"Edit\".

    Navigate to Computer Configuration >> Policies >> Windows Settings >>
Security Settings >> Account Policies >> Kerberos Policy.

    If the value for \"Maximum lifetime for service ticket\" is \"0\" or
greater than \"600\" minutes, this is a finding.
  "
  desc  'fix', "Configure the policy value in the Default Domain Policy for
Computer Configuration >> Policies >> Windows Settings >> Security Settings >>
Account Policies >> Kerberos Policy >> \"Maximum lifetime for service ticket\"
to a maximum of \"600\" minutes, but not \"0\", which equates to \"Ticket
doesn't expire\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag gid: 'V-205703'
  tag rid: 'SV-205703r569188_rule'
  tag stig_id: 'WN19-DC-000030'
  tag fix_id: 'F-5968r355028_fix'
  tag cci: ['CCI-001942', 'CCI-001941']
  tag legacy: ['SV-103531', 'V-93445']
  tag nist: ['IA-2 (9)', 'IA-2 (8)']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe security_policy do
      its('MaxServiceAge') { should be_between(0,600) }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is N/A.' do
      skip 'This system is not a domain controller, therefore this control is N/A.'
    end
  end

end

