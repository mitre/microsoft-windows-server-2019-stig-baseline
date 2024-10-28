# encoding: UTF-8

control "V-93535" do
  title "Windows Server 2019 data files owned by users must be on a different logical partition from the directory server data files."
  desc  "When directory service data files, especially for directories used for identification, authentication, or authorization, reside on the same logical partition as user-owned files, the directory service data may be more vulnerable to unauthorized access or other availability compromises. Directory service and user-owned data files sharing a partition may be configured with less restrictive permissions in order to allow access to the user data.

    The directory service may be vulnerable to a denial of service attack when user-owned files on a common partition are expanded to an extent preventing the directory service from acquiring more space for directory or audit data."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.

    Run \"Regedit\".
    Navigate to \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\".
    Note the directory locations in the values for \"DSA Database file\".
    
    Open \"Command Prompt\".
    Enter \"net share\".
    Note the logical drive(s) or file system partition for any organization-created data shares.
    Ignore system shares (e.g., NETLOGON, SYSVOL, and administrative shares ending in $). User shares that are hidden (ending with $) should not be ignored.

    If user shares are located on the same logical partition as the directory server data files, this is a finding."
  desc  "fix", "Move shares used to store files owned by users to a different logical partition than the directory server data files."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000138-GPOS-00069"
  tag gid: "V-93535"
  tag rid: "SV-103621r1_rule"
  tag stig_id: "WN19-DC-000120"
  tag fix_id: "F-99779r1_fix"
  tag cci: ["CCI-001090"]
  tag nist: ["SC-4", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    dsa_db_file = command('Get-ItemPropertyValue -Path HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters -Name "DSA Database file"').stdout.strip
    net_shares = json({ command: "Get-SMBShare | Where-Object -Property Name -notin C$,ADMIN$,IPC$,NETLOGON,SYSVOL | Select Path | ConvertTo-Json" }).params

    if net_shares.empty?
      impact 0.0
      describe 'No non-default file shares were detected' do
      skip 'This control is NA'
      end
    else
      case net_shares
      when Hash
        net_shares.each do |key, value|
          describe "Net Share path: #{value}" do
            subject { value }
            it { should_not eq dsa_db_file }
          end
        end
      when Array
        net_shares.each do |paths|
          paths.each do |key, value|
            describe "Net Share path: #{value}" do
              subject { value }
              it { should_not eq dsa_db_file }
            end
          end
        end
      end
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end