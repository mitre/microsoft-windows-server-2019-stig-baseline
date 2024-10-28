# encoding: UTF-8

control "V-93195" do
  title "Windows Server 2019 Event Viewer must be protected from unauthorized
modification and deletion."
  desc  "Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    Operating systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools
and the corresponding rights the user enjoys in order to make access decisions
regarding the modification or deletion of audit tools."
  desc  "rationale", ""
  desc  'check', "Navigate to \"%SystemRoot%\\System32\".

    View the permissions on \"Eventvwr.exe\".

    If any groups or accounts other than TrustedInstaller have \"Full control\"
or \"Modify\" permissions, this is a finding.

    The default permissions below satisfy this requirement:

    TrustedInstaller - Full Control
    Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
APPLICATION PACKAGES - Read & Execute"
  desc  'fix', "Configure the permissions on the \"Eventvwr.exe\" file to prevent
modification by any groups or accounts other than TrustedInstaller. The default
permissions listed below satisfy this requirement:

    TrustedInstaller - Full Control
    Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
APPLICATION PACKAGES - Read & Execute

    The default location is the \"%SystemRoot%\\System32\" folder."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000257-GPOS-00098'
  tag 'satisfies': ["SRG-OS-000257-GPOS-00098", "SRG-OS-000258-GPOS-00099"]
  tag 'gid': 'V-93195'
  tag 'rid': 'SV-103283r1_rule'
  tag 'stig_id': 'WN19-AU-000060'
  tag 'fix_id': 'F-99441r1_fix'
  tag 'cci': ["CCI-001494", "CCI-001495"]
  tag 'nist': ["AU-9", "AU-9", "Rev_4"]

  get_system_root = command('Get-ChildItem Env: | Findstr SystemRoot').stdout.strip
  system_root = get_system_root[11..get_system_root.length]

  systemroot = system_root.strip

  eventvwr = <<-EOH
  $output = (Get-Acl -Path #{systemroot}\\SYSTEM32\\Eventvwr.exe).AccessToString
  write-output $output
  EOH

  # raw powershell output
  raw_eventvwr = powershell(eventvwr).stdout.strip

  # clean results cleans up the extra line breaks
  clean_eventvwr = raw_eventvwr.lines.collect(&:strip)

  describe 'Verify the default registry permissions for the keys note below of the C:\Windows\System32\Eventvwr.exe' do
    subject { clean_eventvwr }
    it { should cmp input('eventvwr_perms') }
  end
end

