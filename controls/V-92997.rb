# encoding: UTF-8

control "V-92997" do
  title "Windows Server 2019 Allow log on through Remote Desktop Services user
right must only be assigned to the Administrators group on domain controllers."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    Accounts with the \"Allow log on through Remote Desktop Services\" user
right can access a system through Remote Desktop."
  desc  "rationale", ""
  desc  'check', "This applies to domain controllers, it is NA for other systems.

    Verify the effective setting in Local Group Policy Editor.
    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If any accounts or groups other than the following are granted the \"Allow
log on through Remote Desktop Services\" user right, this is a finding.

    - Administrators

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If any SIDs other than the following are granted the
\"SeRemoteInteractiveLogonRight\" user right, this is a finding.

    S-1-5-32-544 (Administrators)"
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Allow log
on through Remote Desktop Services\" to include only the following accounts or
groups:

    - Administrators"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-92997'
  tag 'rid': 'SV-103085r1_rule'
  tag 'stig_id': 'WN19-DC-000360'
  tag 'fix_id': 'F-99243r1_fix'
  tag 'cci': ["CCI-000213"]
  tag 'nist': ["AC-3", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  end
  if domain_role == '4' || domain_role == '5'
    describe security_policy do
     its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end

