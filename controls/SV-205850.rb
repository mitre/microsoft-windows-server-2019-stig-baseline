# encoding: UTF-8

control 'SV-205850' do
  title 'Windows Server 2019 must use an anti-virus program.'
  desc  "Malicious software can establish a base on individual desktops and
servers. Employing an automated mechanism to detect this type of software will
aid in elimination of the software from the operating system."
  desc  'rationale', ''
  desc  'check', "
    Verify an anti-virus solution is installed on the system. The anti-virus
solution may be bundled with an approved host-based security solution.

    If there is no anti-virus solution installed on the system, this is a
finding.

    Verify if Windows Defender is in use or enabled:

    Open \"PowerShell\".

    Enter “get-service | where {$_.DisplayName -Like \"*Defender*\"} | Select
Status,DisplayName”

    Verify if third-party anti-virus is in use or enabled:

    Open \"PowerShell\".

    Enter \"get-service | where {$_.DisplayName -Like \"*mcafee*\"} | Select
Status,DisplayName”

    Enter \"get-service | where {$_.DisplayName -Like \"*symantec*\"} | Select
Status,DisplayName”

  "
  desc  'fix', "
    If no anti-virus software is in use, install Windows Defender or
third-party anti-virus.

    Open \"PowerShell\".

    Enter \"Install-WindowsFeature -Name Windows-Defender”.

    For third-party anti-virus, install per anti-virus instructions and disable
Windows Defender.

    Open \"PowerShell\".

    Enter \"Uninstall-WindowsFeature -Name Windows-Defender”.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205850'
  tag rid: 'SV-205850r569245_rule'
  tag stig_id: 'WN19-00-000110'
  tag fix_id: 'F-6115r603168_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['SV-103305', 'V-93217']
  tag nist: ['CM-6 b']

  describe.one do
    describe registry_key('HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion') do
      it { should exist }
    end
    describe registry_key('HKLM\SOFTWARE\McAfee/DesktopProtection\szProductVer') do
      it { should exist }
    end
    describe registry_key('HKLM\SOFTWARE\McAfee\Endpoint\AV') do
      it { should exist }
      it { should have_property 'ProductVersion' }
    end
  end

end

