# encoding: UTF-8

control "V-93473" do
  title "Windows Server 2019 passwords for the built-in Administrator account must be changed at least every 60 days."
  desc  "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password not may be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.
    Organizations that use an automated tool, such Microsoft's Local Administrator Password Solution (LAPS), on domain-joined systems can configure this to occur more frequently. LAPS will change the password every \"30\" days by default."
  desc  "rationale", ""
  desc  "check", "Review the password last set date for the built-in Administrator account.
    Domain controllers:
    Open \"PowerShell\".
    Enter \"Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like \"*-500\" | Ft Name, SID, PasswordLastSet\".
    If the \"PasswordLastSet\" date is greater than \"60\" days old, this is a finding.
    Member servers and standalone systems:
    Open \"Command Prompt\".
    Enter 'Net User [account name] | Find /i \"Password Last Set\"', where [account name] is the name of the built-in administrator account.
    (The name of the built-in Administrator account must be changed to something other than \"Administrator\" per STIG requirements.)
    If the \"PasswordLastSet\" date is greater than \"60\" days old, this is a finding."
  desc  "fix", "Change the built-in Administrator account password at least every \"60\" days.
    Automated tools, such as Microsoft's LAPS, may be used on domain-joined member servers to accomplish this."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000076-GPOS-00044"
  tag gid: "V-93473"
  tag rid: "SV-103559r1_rule"
  tag stig_id: "WN19-00-000020"
  tag fix_id: "F-99717r1_fix"
  tag cci: ["CCI-000199"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]

  #check out Windows 2012 control 'V-14225'

  # SK: Copied from Windows 2012 V-14225
  # Q: Review code and run tests

  administrator = input('local_administrator')
  # returns a hash of {'Enabled' => 'true' } 
  is_domain_controller = json({ command: 'Get-ADDomainController | Select Enabled | ConvertTo-Json' })

   if (is_domain_controller['Enabled'] == true)
    
     password_set_date = json({ command: "Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where-Object {$_.SID -like '*-500' -and $_.PasswordLastSet -lt ((Get-Date).AddDays(-365))} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json" })
     date = password_set_date["DateTime"]
     if (date == nil)
      describe 'Administrator Account is within 365 days since password change' do
        skip 'Administrator Account is within 365 days since password change'
      end
    else
       describe 'Password Last Set' do
         it 'Administrator Account Password Last Set Date is' do
         failure_message = "Password Date should not be more that 365 Days: #{date}"
         expect(date).to be_empty, failure_message
        end
       end
      end
   end
   if (is_domain_controller.params == {} )
   # Input local_administrator is critical here
   local_password_set_date = json({ command: "Get-LocalUser -name #{administrator} | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-365)} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json"})
   local_date =  local_password_set_date["DateTime"]
    if (local_date == nil)
      describe 'Local Administrator Account is within 365 days since password change' do
        skip 'Local Administrator Account is within 365 days since password change'
      end
    else
       describe 'Password Last Set' do
         it 'Local Administrator Account Password Last Set Date is' do
         failure_message = "Password Date should not be more that 365 Days: #{local_date}"
         expect(local_date).to be_empty, failure_message
        end
       end
      end
   end

end