# encoding: UTF-8

control "V-93563" do
  title "Windows Server 2019 Explorer Data Execution Prevention must be enabled."
  desc  "Data Execution Prevention provides additional protection by performing checks on memory to help prevent malicious code from running. This setting will prevent Data Execution Prevention from being turned off for File Explorer."
  desc  "rationale", ""
  desc  "check", "The default behavior is for Data Execution Prevention to be turned on for File Explorer.
    If the registry value name below does not exist, this is not a finding.
    If it exists and is configured with a value of \"0\", this is not a finding.
    If it exists and is configured with a value of \"1\", this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

    Value Name: NoDataExecutionPrevention

    Value Type: REG_DWORD
    Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc  "fix", "The default behavior is for data execution prevention to be turned on for File Explorer. If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> File Explorer >> \"Turn off Data Execution Prevention for Explorer\" to \"Not Configured\" or \"Disabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000433-GPOS-00192"
  tag gid: "V-93563"
  tag rid: "SV-103649r1_rule"
  tag stig_id: "WN19-CC-000310"
  tag fix_id: "F-99807r1_fix"
  tag cci: ["CCI-002824"]
  tag nist: ["SI-16", "Rev_4"]

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer').has_property?('NoDataExecutionPrevention')
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    its('NoDataExecutionPrevention') { should cmp 0 }
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should_not have_property 'NoDataExecutionPrevention' }
    end
  end
end