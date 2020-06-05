# encoding: UTF-8

control "V-93531" do
  title "Windows Server 2019 non-system-created file shares must limit access to groups that require it."
  desc  "Shares on a system provide network access. To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to accounts that require it."
  desc  "rationale", ""
  desc  "check", "If only system-created shares such as \"ADMIN$\", \"C$\", and \"IPC$\" exist on the system, this is NA. (System-created shares will display a message that it has been shared for administrative purposes when \"Properties\" is selected.)

    Run \"Computer Management\".
    Navigate to System Tools >> Shared Folders >> Shares.
    Right-click any non-system-created shares.
    Select \"Properties\".
    Select the \"Share Permissions\" tab.

    If the file shares have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding.

    Select the \"Security\" tab.

    If the permissions have not been configured to restrict permissions to the specific groups or accounts that require access, this is a finding."
  desc  "fix", "If a non-system-created share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.
    Remove any unnecessary non-system-created shares."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000138-GPOS-00069"
  tag gid: "V-93531"
  tag rid: "SV-103617r1_rule"
  tag stig_id: "WN19-00-000230"
  tag fix_id: "F-99775r1_fix"
  tag cci: ["CCI-001090"]
  tag nist: ["SC-4", "Rev_4"]

  # control 'V-3245' windows 2012 Profile

  # SK: Copied from Windows 2012 V-3245
  # SK: Test - passed

  share_names = []
  share_paths = []
  get = command('Get-WMIObject -Query "SELECT * FROM Win32_Share" | Findstr /V "Name --"').stdout.strip.split("\n")

  get.each do |share|
    loc_space = share.index(' ')
    names = share[0..loc_space-1]
    share_names.push(names)
    path = share[9..50]
    share_paths.push(path)
  end

  share_names_string = share_names.join(',')

  if share_names_string != 'ADMIN$,C$,IPC$'
    [share_paths, share_names].each do |path1, _name1|
      describe command("Get-Acl -Path '#{path1}' | Format-List | Findstr /i /C:'Everyone Allow'") do
        its('stdout') { should eq '' }
      end
    end
  else # share_names_string == 'ADMIN$,C$,IPC$'
    impact 0.0
    describe 'The default files shares exist' do
      skip 'This control is NA'
    end
  end
end