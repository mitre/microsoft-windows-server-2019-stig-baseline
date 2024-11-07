control 'SV-205877' do
  title 'The password for the krbtgt account on a domain must be reset at least every 180 days.'
  desc 'The krbtgt account acts as a service account for the Kerberos Key Distribution Center (KDC) service.  The account and password are created when a domain is created and the password is typically not changed.  If the krbtgt account is compromised, attackers can create valid Kerberos Ticket Granting Tickets (TGT).

The password must be changed twice to effectively remove the password history. Changing once, waiting for replication to complete and the amount of time equal to or greater than the maximum Kerberos ticket lifetime, and changing again reduces the risk of issues.'
  desc 'check', 'This requirement is applicable to domain controllers; it is NA for other systems. 

Open "Windows PowerShell".

Enter "Get-ADUser krbtgt -Property PasswordLastSet".

If the "PasswordLastSet" date is more than 180 days old, this is a finding.'
  desc 'fix', 'Reset the password for the krbtgt account a least every 180 days. The password must be changed twice to effectively remove the password history. Changing once, waiting for replication to complete and changing again reduces the risk of issues. Changing twice in rapid succession forces clients to reauthenticate (including application services) but is desired if a compromise is suspected.

PowerShell scripts are available to accomplish this such as at the following link:

https://docs.microsoft.com/en-us/answers/questions/97108/resetting-the-krbtgt-account-password-in-a-domain.html

All scripts should be tested.

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Select "Advanced Features" in the "View" menu if not previously selected.

Select the "Users" node.

Right-click on the krbtgt account and select "Reset password".

Enter a password that meets password complexity requirements.

Clear the "User must change password at next logon" check box.

The system will automatically change this to a system-generated complex password.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205877'
  tag rid: 'SV-205877r991589_rule'
  tag stig_id: 'WN19-DC-000430'
  tag fix_id: 'F-6142r857314_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    password_set_date = json(command: 'New-TimeSpan -Start (Get-ADUser krbtgt -Property PasswordLastSet).PAsswordLastSet | where -filter { $_.Days -gt 180 } | ConvertTo-JSON').params
    date = password_set_date['Days']
    if date.nil?
      describe 'krbtgt Account is within 180 days since password change' do
        subject { date }
        its(date) { should eq nil }
      end
    else
      describe 'Password Last Set' do
        it 'krbtgt Account Password Last Set Date is' do
          failure_message = "Password Date should not be more than 180 Days: #{date}"
          expect(date).to be_empty, failure_message
        end
      end
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end