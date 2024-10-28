control 'V-93531' do
  title 'Windows Server 2019 non-system-created file shares must limit access to groups that require it.'
  desc  'Shares on a system provide network access. To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to accounts that require it.'
  desc  'rationale', ''
  desc  'check', "If only system-created shares such as \"ADMIN$\", \"C$\", and \"IPC$\" exist on the system, this is NA. (System-created shares will display a message that it has been shared for administrative purposes when \"Properties\" is selected.)

    Run \"Computer Management\".
    Navigate to System Tools >> Shared Folders >> Shares.
    Right-click any non-system-created shares.
    Select \"Properties\".
    Select the \"Share Permissions\" tab.
    If the file shares have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.
    Select the \"Security\" tab.
    If the permissions have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding."
  desc  'fix', "If a non-system-created share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.
    Remove any unnecessary non-system-created shares."
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-93531'
  tag rid: 'SV-103617r1_rule'
  tag stig_id: 'WN19-00-000230'
  tag fix_id: 'F-99775r1_fix'
  tag cci: ['CCI-001090']
  tag nist: %w(SC-4 Rev_4)

  net_shares = json({ command: 'Get-SMBShare -Special $false | Where-Object -Property Name -notin C$,ADMIN$,IPC$,NETLOGON,SYSVOL | Select Name, Path | ConvertTo-Json' }).params

  if net_shares.empty?
    impact 0.0
    describe 'No non-default file shares were detected' do
      skip 'This control is NA'
    end
  else
    case net_shares
    when Hash
      net_shares.each do |_key, value|
        describe 'Unrestricted file shares' do
          subject { command("Get-Acl -Path '#{value}' | ?{$_.AccessToString -match 'Everyone\sAllow'} | %{($_.PSPath -split '::')[1]}") }
          its('stdout') { should eq '' }
        end
      end
    when Array
      net_shares.each do |paths|
        paths.each do |_key, value|
          describe 'Unrestricted file shares' do
            subject { command("Get-Acl -Path '#{value}' | ?{$_.AccessToString -match 'Everyone\sAllow'} | %{($_.PSPath -split '::')[1]}") }
            its('stdout') { should eq '' }
          end
        end
      end
    end
  end
end
