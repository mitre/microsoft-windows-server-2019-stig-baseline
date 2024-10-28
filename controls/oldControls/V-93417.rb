# encoding: UTF-8

control "V-93417" do
  title "Windows Server 2019 domain controllers must run on a machine dedicated to that function."
  desc  "Executing application servers on the same host machine with a directory server may substantially weaken the security of the directory server. Web or database server applications usually require the addition of many programs and accounts, increasing the attack surface of the computer.

    Some applications require the addition of privileged accounts, providing potential sources of compromise. Some applications (such as Microsoft Exchange) may require the use of network ports or services conflicting with the directory server. In this case, non-standard ports might be selected, and this could interfere with intrusion detection or prevention services."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers, it is NA for other systems.

    Review the installed roles the domain controller is supporting.
    Start \"Server Manager\".
    Select \"AD DS\" in the left pane and the server name under \"Servers\" to the right.
    Select \"Add (or Remove) Roles and Features\" from \"Tasks\" in the \"Roles and Features\" section. (Cancel before any changes are made.)
    Determine if any additional server roles are installed. A basic domain controller setup will include the following:

    - Active Directory Domain Services
    - DNS Server
    - File and Storage Services

    If any roles not requiring installation on a domain controller are installed, this is a finding.
    A Domain Name System (DNS) server integrated with the directory server (e.g., AD-integrated DNS) is an acceptable application. However, the DNS server must comply with the DNS STIG security requirements.
    Run \"Programs and Features\".
    Review installed applications.
    If any applications are installed that are not required for the domain controller, this is a finding."
  desc  "fix", "Remove additional roles or applications such as web, database, and email from the domain controller."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000095-GPOS-00049"
  tag gid: "V-93417"
  tag rid: "SV-103503r1_rule"
  tag stig_id: "WN19-DC-000130"
  tag fix_id: "F-99661r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    role_list = [
      "Active Directory Domain Services",
      "DNS Server",
      "File and Storage Services"
    ]
    roles = json(command: "Get-WindowsFeature | Where {($_.installstate -eq 'installed') -and ($_.featuretype -eq 'role')} | foreach { $_.DisplayName } | ConvertTo-JSON").params
    describe "The list of roles installed on the server" do
      subject { roles }
      it { should be_in role_list }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end