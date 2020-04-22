# encoding: UTF-8

control "V-93457" do
  title "Windows Server 2019 outdated or unused accounts must be removed or
disabled."
  desc  "Outdated or unused accounts provide penetration points that may go
undetected. Inactive accounts must be deleted if no longer necessary or, if
still required, disabled until needed."
  desc  "rationale", ""
  desc  "check", "
    Open \"Windows PowerShell\".

    Domain Controllers:

    Enter \"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00\"

    This will return accounts that have not been logged on to for 35 days,
along with various attributes such as the Enabled status and LastLogonDate.

    Member servers and standalone systems:

    Copy or enter the lines below to the PowerShell window and enter. (Entering
twice may be required. Do not include the quotes at the beginning and end of
the query.)

    \"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
$_.SchemaClassName -eq 'user' } | ForEach {
     $user = ([ADSI]$_.Path)
     $lastLogin = $user.Properties.LastLogin.Value
     $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
     if ($lastLogin -eq $null) {
     $lastLogin = 'Never'
     }
     Write-Host $user.Name $lastLogin $enabled
    }\"

    This will return a list of local accounts with the account name, last
logon, and if the account is enabled (True/False).
    For example: User1 10/31/2015 5:49:56 AM True

    Review the list of accounts returned by the above queries to determine the
finding validity for each account reported.

    Exclude the following accounts:

    - Built-in administrator account (Renamed, SID ending in 500)
    - Built-in guest account (Renamed, Disabled, SID ending in 501)
    - Application accounts

    If any enabled accounts have not been logged on to within the past 35 days,
this is a finding.

    Inactive accounts that have been reviewed and deemed to be required must be
documented with the ISSO.
  "
  desc  "fix", "Regularly review accounts to determine if they are still
active. Remove or disable accounts that have not been used in the last 35 days."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000118-GPOS-00060"
  tag gid: "V-93457"
  tag rid: "SV-103543r1_rule"
  tag stig_id: "WN19-00-000190"
  tag fix_id: "F-99701r1_fix"
  tag cci: ["CCI-000795"]
  tag nist: ["IA-4 e", "Rev_4"]
end

