# encoding: UTF-8

control "V-93179" do
  title "Windows Server 2019 Security event log size must be configured to
196608 KB or greater."
  desc  "Inadequate log size will cause the log to fill up quickly. This may
prevent audit events from being recorded properly and require frequent
attention by administrative personnel."
  desc  "rationale", ""
  desc  'check', "If the system is configured to write events directly to an audit server,
this is NA.

    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

    Value Name: MaxSize

    Type: REG_DWORD
    Value: 0x00030000 (196608) (or greater)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Event Log Service >> Security
>> \"Specify the maximum log file size (KB)\" to \"Enabled\" with a \"Maximum
Log Size (KB)\" of \"196608\" or greater."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000341-GPOS-00132'
  tag 'gid': 'V-93179'
  tag 'rid': 'SV-103267r1_rule'
  tag 'stig_id': 'WN19-CC-000280'
  tag 'fix_id': 'F-99425r1_fix'
  tag 'cci': ["CCI-001849"]
  tag 'nist': ["AU-4", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 196608 }
  end
end

