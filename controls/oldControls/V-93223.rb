# encoding: UTF-8

control "V-93223" do
  title "Windows Server 2019 FTP servers must be configured to prevent
anonymous logons."
  desc  "The FTP service allows remote users to access shared files and
directories. Allowing anonymous FTP connections makes user auditing difficult.

    Using accounts that have administrator privileges to log on to FTP risks
that the userid and password will be captured on the network and give
administrator access to an unauthorized user."
  desc  "rationale", ""
  desc  'check', "If FTP is not installed on the system, this is NA.

    Open \"Internet Information Services (IIS) Manager\".

    Select the server.

    Double-click \"FTP Authentication\".

    If the \"Anonymous Authentication\" status is \"Enabled\", this is a
finding."
  desc  'fix', "Configure the FTP service to prevent anonymous logons.

    Open \"Internet Information Services (IIS) Manager\".

    Select the server.

    Double-click \"FTP Authentication\".

    Select \"Anonymous Authentication\".

    Select \"Disabled\" under \"Actions\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93223'
  tag 'rid': 'SV-103311r1_rule'
  tag 'stig_id': 'WN19-00-000420'
  tag 'fix_id': 'F-99469r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  is_ftp_installed = command('Get-WindowsFeature Web-Ftp-Server | Select -Expand Installed').stdout.strip
   if is_ftp_installed == 'False'
    impact 0.0
    describe 'FTP is not installed' do
      skip 'Control not applicable'
    end
   else
    describe 'File Transfer Protocol (FTP) servers must be configured to prevent anonymous logons' do
      skip 'is a manual check'
    end
   end
end

