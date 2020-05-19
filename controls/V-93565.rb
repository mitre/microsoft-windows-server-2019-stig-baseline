# encoding: UTF-8

control "V-93565" do
  title "Windows Server 2019 Exploit Protection system-level mitigation, Randomize memory allocations (Bottom-Up ASLR), must be on."
  desc  "Exploit protection enables mitigations against potential threats at the system and application level.  Several mitigations, including \"Randomize memory allocations (Bottom-Up ASLR)\", are enabled by default at the system level. Bottom-Up ASLR (address space layout randomization) randomizes locations for virtual memory allocations, including those for system structures. If this is turned off, Windows may be subject to various exploits."
  desc  "rationale", ""
  desc  "check", "This is applicable to unclassified systems, for other systems this is NA. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.
    The PowerShell query results for this show as \"NOTSET\".
    Run \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Get-ProcessMitigation -System\".
    If the status of \"ASLR: BottomUp\" is \"OFF\", this is a finding.
    Values that would not be a finding include:
    ON
    NOTSET (Default configuration)"
  desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Randomize memory allocations (Bottom-Up ASLR)\" is turned on. The default configuration in Exploit Protection is \"On by default\" which meets this requirement.
    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Randomize memory allocations
    (Bottom-Up ASLR)\" to \"On by default\" or \"Use default (<On>)\".

    The STIG package includes a DoD EP XML file in the \"Supporting Files\" folder for configuring application mitigations defined in the STIG. This can also be modified to explicitly enforce the system level requirements. Adding the following to the XML file will explicitly turn Bottom-Up ASLR on (other system level EP requirements can be combined under <SystemConfig>):
    <SystemConfig>
      <ASLR BottomUp=\"true\" HighEntropy=\"true\"></ASLR>
    </SystemConfig>

    The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> \"Use a common set of exploit protection settings\" configured to \"Enabled\" with file name and location defined under \"Options:\". It is recommended the file be in a read-only network location."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000433-GPOS-00193"
  tag gid: "V-93565"
  tag rid: "SV-103651r1_rule"
  tag stig_id: "WN19-EP-000020"
  tag fix_id: "F-99809r1_fix"
  tag cci: ["CCI-002824"]
  tag nist: ["SI-16", "Rev_4"]

  #Code can be found in Windows 10
  # SK: Copied from Windows 10 V-77095
  # Q: HighEntropy=\"true\ added

  aslr_bottomup_script = <<-EOH
  $convert_json = Get-ProcessMitigation -System | ConvertTo-Json
  $convert_out_json = ConvertFrom-Json -InputObject $convert_json
  $select_object = $convert_out_json.Aslr | Select BottomUp
  $result = $select_object.BottomUp
  write-output $result
  EOH

  if input('sensitive_system') == 'true' || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  elsif registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId < '1709'
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1709.' do
      skip 'This STIG does not apply to Prior Versions before 1709.'
    end
  else
    describe 'ALSR BottomUp is required to be enabled on System' do
      subject { powershell(aslr_bottomup_script).strip }
      it { should_not eq '2' }
    end
  end

end

