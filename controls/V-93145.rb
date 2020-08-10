# encoding: UTF-8

control "V-93145" do
  title "Windows Server 2019 account lockout duration must be configured to 15
minutes or greater."
  desc  "The account lockout feature, when enabled, prevents brute-force
password attacks on the system. This parameter specifies the period of time
that an account will remain locked after the specified number of failed logon
attempts."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

    If the \"Account lockout duration\" is less than \"15\" minutes (excluding
\"0\"), this is a finding.

    For server core installations, run the following command:

    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

    If \"LockoutDuration\" is less than \"15\" (excluding \"0\") in the file,
this is a finding.

    Configuring this to \"0\", requiring an administrator to unlock the
account, is more restrictive and is not a finding."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Account Policies >> Account Lockout Policy >> \"Account
lockout duration\" to \"15\" minutes or greater.

    A value of \"0\" is also acceptable, requiring an administrator to unlock
the account."
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag gid: 'V-93145'
  tag rid: 'SV-103233r1_rule'
  tag stig_id: 'WN19-AC-000010'
  tag fix_id: 'F-99391r1_fix'
  tag cci: ["CCI-002238"]
  tag nist: ["AC-7 b", "Rev_4"]

  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip
  
  if os_type == 'False'
     describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
     end
  else
  pass_lock_duration = input('pass_lock_duration')
  describe.one do
    describe security_policy do
      its('LockoutDuration') { should be >= pass_lock_duration }
    end
    describe security_policy do
      its('LockoutDuration') { should cmp == 0 }
    end
  end
 end
end

