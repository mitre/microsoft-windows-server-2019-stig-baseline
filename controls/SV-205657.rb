control 'SV-205657' do
  title 'Windows Server 2019 passwords for the built-in Administrator account must be changed at least every 60 days.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password might not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

Windows LAPS must be used to change the built-in Administrator account password.'
  desc 'check', 'If there are no enabled local Administrator accounts, this is Not Applicable.

Review the password last set date for the enabled local Administrator account.

On the stand alone or domain-joined workstation:

Open "PowerShell".

Enter "Get-LocalUser -Name * | Select-Object *".

If the "PasswordLastSet" date is greater than "60" days old for the local Administrator account for administering the computer/domain, this is a finding.

Verify LAPS is configured and operational.

Navigate to Local Computer Policy >> Computer Configuration >> Administrative Templates >> System >> LAPS >> Password Settings >> Set to enabled. Password Complexity, large letters + small letters + numbers + special, Password Length 14, Password Age 60. If not configured as shown, this is a finding.

Navigate to Local Computer Policy >> Computer Configuration >> Administrative Templates >> System >> LAPS >> Password Settings >> Name of administrator Account to manage >> Set to enabled >> Administrator account name is populated. If it is not, this is a finding.

Verify LAPS Operational logs >> Event Viewer >> Applications and Services Logs >> Microsoft >> Windows >> LAPS >> Operational. Verify LAPS policy process is completing. If it is not, this is a finding.'
  desc 'fix', 'Change the enabled local Administrator account password at least every 60 days. Windows LAPS must be used to change the built-in Administrator account password. Domain-joined systems can configure this to occur more frequently. LAPS will change the password every 30 days by default.

More information is available at:
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/by-popular-demand-windows-laps-available-now/ba-p/3788747
https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview#windows-laps-supported-platforms-and-azure-ad-laps-preview-status'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-205657'
  tag rid: 'SV-205657r1000123_rule'
  tag stig_id: 'WN19-00-000020'
  tag fix_id: 'F-5922r951106_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']

  administrator = input('local_administrator')

  # local_password_set_date = JSON.parse(command("Get-LocalUser -name #{administrator} | Select-Object passwordLastSet | ConvertTo-Json").stdout.strip)
  # puts "pw: #{local_password_set_date['PasswordLastSet']}"

  local_password_set_date = json({ command: "Get-LocalUser -name #{administrator} | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-60)} | Select-Object -ExpandProperty PasswordLastSet | ConvertTo-Json" })
  local_date = local_password_set_date['DateTime']
  describe 'Password Last Set Date' do
    it 'The built-in Administrator account must be changed at least every 60 days.' do
      expect(local_date).to be_nil
    end
  end

  # Verify LAPS configuration

  #Try with registry instead
  describe registry_key('HKLM\Software\Policies\Microsoft Services\AdmPwd') do
    its('PasswordSettings') { should eq 1 }
  end


  # laps_config = command('Get-GPResultantSetOfPolicy -Computer -ReportType XML | Select-String -Pattern "LAPS"').stdout
  # describe 'LAPS Configuration' do
  #   it 'LAPS must be configured and operational.' do
  #     expect(laps_config).not_to be_empty
  #   end
  # end

  # # Verify LAPS operational logs
  # laps_logs = command('Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" | Select-Object -First 1').stdout
  # describe 'LAPS Operational Logs' do
  #   it 'LAPS policy process must be completing.' do
  #     expect(laps_logs).not_to be_empty
  #   end
  # end

end
