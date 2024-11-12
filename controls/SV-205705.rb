control 'SV-205705' do
  title 'Windows Server 2019 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.'
  desc "This setting determines the period of time (in days) during which a user's TGT may be renewed. This security configuration limits the amount of time an attacker has to crack the TGT and gain access."
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain).

Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum lifetime for user ticket renewal" is greater than "7" days, this is a finding.'
  desc 'fix', 'Configure the policy value in the Default Domain Policy for Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy >> "Maximum lifetime for user ticket renewal" to a maximum of "7" days or less.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag gid: 'V-205705'
  tag rid: 'SV-205705r1000143_rule'
  tag stig_id: 'WN19-DC-000050'
  tag fix_id: 'F-5970r355034_fix'
  tag cci: ['CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if ['4', '5'].include?(domain_role)
    describe security_policy do
      its('MaxRenewAge') { should be <= 7 }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end
