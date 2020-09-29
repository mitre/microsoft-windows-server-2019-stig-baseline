# encoding: UTF-8

control "V-92999" do
  title "Windows Server 2019 Deny access to this computer from the network user
right on domain controllers must be configured to prevent unauthenticated
access."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high-level capabilities.

    The \"Deny access to this computer from the network\" user right defines
the accounts that are prevented from logging on from the network.

    The Guests group must be assigned this right to prevent unauthenticated
access."
  desc  "rationale", ""
  desc  'check', "This applies to domain controllers. A separate version applies to other
systems.

    Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    If the following accounts or groups are not defined for the \"Deny access
to this computer from the network\" user right, this is a finding:

    - Guests Group

    For server core installations, run the following command:

    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

    Review the text file.

    If the following SIDs are not defined for the \"SeDenyNetworkLogonRight\"
user right, this is a finding.

    S-1-5-32-546 (Guests)"
  desc  'fix', "
    Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment >> \"Deny
access to this computer from the network\" to include the following:

    - Guests Group"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-92999'
  tag 'rid': 'SV-103087r1_rule'
  tag 'stig_id': 'WN19-DC-000370'
  tag 'fix_id': 'F-99245r1_fix'
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
     its('SeDenyNetworkLogonRight') { should eq ['S-1-5-32-546'] }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end

