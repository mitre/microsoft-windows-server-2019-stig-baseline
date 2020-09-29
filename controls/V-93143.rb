# encoding: UTF-8

control "V-93143" do
  title "Windows Server 2019 must have the period of time before the bad logon
counter is reset configured to 15 minutes or greater."
  desc  "The account lockout feature, when enabled, prevents brute-force
password attacks on the system. This parameter specifies the period of time
that must pass after failed logon attempts before the counter is reset to
\"0\". The smaller this value is, the less effective the account lockout
feature will be in protecting the local system."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

    If the \"Reset account lockout counter after\" value is less than \"15\"
minutes, this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

    If \"ResetLockoutCount\" is less than \"15\" in the file, this is a finding."
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Account Policies >> Account Lockout
Policy >> \"Reset account lockout counter after\" to at least \"15\" minutes."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000021-GPOS-00005'
  tag 'satisfies': ["SRG-OS-000021-GPOS-00005", "SRG-OS-000329-GPOS-00128"]
  tag 'gid': 'V-93143'
  tag 'rid': 'SV-103231r1_rule'
  tag 'stig_id': 'WN19-AC-000030'
  tag 'fix_id': 'F-99389r1_fix'
  tag 'cci': ["CCI-000044", "CCI-002238"]
  tag 'nist': ["AC-7 a", "AC-7 b", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip
  
  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
  describe security_policy do
    its('ResetLockoutCount') { should be >= input('pass_lock_time') }
  end
 end
end

