control 'V-93029' do
  title "Windows Server 2019 permissions on the Active Directory data files
must only allow System and Administrators access."
  desc  "Improper access permissions for directory data-related files could
allow unauthorized users to read, modify, or delete directory data or audit
trails."
  desc  'rationale', ''
  desc  'check', "This applies to domain controllers. It is NA for other systems.

    Run \"Regedit\".

    Navigate to
\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\".

    Note the directory locations in the values for:

    Database log files path
    DSA Database file

    By default, they will be \\Windows\\NTDS.

    If the locations are different, the following will need to be run for each.

    Open \"Command Prompt (Admin)\".

    Navigate to the NTDS directory (\\Windows\\NTDS by default).

    Run \"icacls *.*\".

    If the permissions on each file are not as restrictive as the following,
this is a finding:

    NT AUTHORITY\\SYSTEM:(I)(F)
    BUILTIN\\Administrators:(I)(F)

    (I) - permission inherited from parent container
    (F) - full access"
  desc  'fix', "Maintain the permissions on NTDS database and log files as follows:

    NT AUTHORITY\\SYSTEM:(I)(F)
    BUILTIN\\Administrators:(I)(F)

    (I) - permission inherited from parent container
    (F) - full access"
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93029'
  tag 'rid': 'SV-103117r1_rule'
  tag 'stig_id': 'WN19-DC-000070'
  tag 'fix_id': 'F-99275r1_fix'
  tag 'cci': ['CCI-002235']
  tag 'nist': ['AC-6 (10)', 'Rev_4']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  # Command Gets the Location of the Property Required
  ntds_database_logs_files_path = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "Database log files path" | ConvertTo-Json').params
  # Command Gets the Location of the Property Required
  ntds_dsa_working_directory = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "DSA Working Directory" | ConvertTo-Json').params
  expected_permissions = input('ntds_permissions')
  if domain_role == '4' || domain_role == '5'
    if ntds_database_logs_files_path == ntds_dsa_working_directory
      perms = json(command: "icacls '#{ntds_dsa_working_directory}\\*.*' | convertto-json").params.map(&:strip)[0..-3].map { |e| e.gsub(/^[^\s]*\s/, '') }.reject(&:empty?)
      describe "Permissions on each file in #{ntds_dsa_working_directory} is set" do
        subject { (perms - expected_permissions).empty? }
        it { should eq true }
      end
    else
      # Command Gets Permissions on Folder Path
      icacls_permissions_ntds_logs = json(command: "icacls '#{ntds_database_logs_files_path}\\*.*' | ConvertTo-Json").params.map(&:strip)[0..-3].map { |e| e.gsub(/^[^\s]*\s/, '') }.reject(&:empty?)
      # Command Gets the Location of the Property Required
      ntds_dsa_file_path = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "DSA Database file" | ConvertTo-Json').params
      # Command Gets Permissions on file ntds.dit
      icacls_permissions_ntds_dsa_file = json(command: "icacls '#{ntds_dsa_file_path}' | ConvertTo-Json").params.map(&:strip)[0..-3].map { |e| e.gsub("#{ntds_dsa_file_path} ", '') }
      describe 'Permissions on NTDS Database Log Files Path is set to' do
        subject { (icacls_permissions_ntds_logs - expected_permissions).empty? }
        it { should eq true }
      end
      describe 'Permissions on NTDS Database DSA File is set to' do
        subject { (icacls_permissions_ntds_dsa_file - expected_permissions).empty? }
        it { should eq true }
      end
    end
  else
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
