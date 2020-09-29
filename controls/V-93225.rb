# encoding: UTF-8

control "V-93225" do
  title "Windows Server 2019 FTP servers must be configured to prevent access
to the system drive."
  desc  "The FTP service allows remote users to access shared files and
directories that could provide access to system resources and compromise the
system, especially if the user can gain access to the root directory of the
boot drive."
  desc  "rationale", ""
  desc  'check', "If FTP is not installed on the system, this is NA.

    Open \"Internet Information Services (IIS) Manager\".

    Select \"Sites\" under the server name.

    For any sites with a Binding that lists FTP, right-click the site and
select \"Explore\".

    If the site is not defined to a specific folder for shared FTP resources,
this is a finding.

    If the site includes any system areas such as root of the drive, Program
Files, or Windows directories, this is a finding."
  desc  'fix', "Configure the FTP sites to allow access only to specific FTP
shared resources. Do not allow access to other areas of the system."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93225'
  tag 'rid': 'SV-103313r1_rule'
  tag 'stig_id': 'WN19-00-000430'
  tag 'fix_id': 'F-99471r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  is_ftp_installed = command('Get-WindowsFeature Web-Ftp-Server | Select -Expand Installed').stdout.strip
   if is_ftp_installed == 'False'
    impact 0.0
    describe 'FTP is not installed' do
      skip 'Control not applicable'
    end
   else
    describe 'Configure the FTP sites to allow access only to specific FTP shared resources. Do not allow access to other areas of the system.' do
      skip 'Configure the FTP sites to allow access only to specific FTP shared resources. Do not allow access to other areas of the system.'
    end
   end
end

