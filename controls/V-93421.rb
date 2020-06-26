# encoding: UTF-8

control "V-93421" do
  title "Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization."
  desc  "Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption."
  desc  "rationale", ""
  desc  "check", "If the server has the role of an FTP server, this is NA.

    Open \"PowerShell\".
    Enter \"Get-WindowsFeature | Where Name -eq Web-Ftp-Service\".
    If \"Installed State\" is \"Installed\", this is a finding.
    An Installed State of \"Available\" or \"Removed\" is not a finding.
    If the system has the role of an FTP server, this must be documented with the ISSO."
  desc  "fix", "Uninstall the \"FTP Server\" role.

    Start \"Server Manager\".
    Select the server with the role.
    Scroll down to \"ROLES AND FEATURES\" in the right pane.
    Select \"Remove Roles and Features\" from the drop-down \"TASKS\" list.
    Select the appropriate server on the \"Server Selection\" page and click \"Next\".
    Deselect \"FTP Server\" under \"Web Server (IIS)\" on the \"Roles\" page.
    Click \"Next\" and \"Remove\" as prompted."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000096-GPOS-00050"
  tag gid: "V-93421"
  tag rid: "SV-103507r1_rule"
  tag stig_id: "WN19-00-000330"
  tag fix_id: "F-99665r1_fix"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b", "Rev_4"]

  ftp_server_state = command('Get-WindowsFeature Web-Ftp-Server | Select -Expand Installed').stdout.strip

  if input('ftp_server') == false
    describe 'Microsoft FTP service must not be installed unless required' do
      subject { ftp_server_state }
      it { should eq 'False' }
    end
  else
    impact 0.0
    describe 'This server has the role of an FTP server, therefore this control is NA' do
      skip 'This server has the role of an FTP server, therefore this control is NA'
    end
  end
end