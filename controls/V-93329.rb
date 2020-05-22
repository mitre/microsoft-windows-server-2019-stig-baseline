# encoding: UTF-8

control "V-93329" do
  title "Windows Server 2019 Exploit Protection mitigations must be configured for firefox.exe."
  desc  "Exploit protection provides a means of enabling additional mitigations against potential threats at the system and application level. Without these additional application protections, Windows may be subject to various exploits."
  desc  "rationale", ""
  desc  "check", "If the referenced application is not installed on the system, this is NA.

    This is applicable to unclassified systems, for other systems this is NA.

    Run \"Windows PowerShell\" with elevated privileges (run as administrator).

    Enter \"Get-ProcessMitigation -Name firefox.exe\".
    (Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured.)

    If the following mitigations do not have a status of \"ON\", this is a finding:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    The PowerShell command produces a list of mitigations; only those with a required status of \"ON\" are listed here."
  desc  "fix", "Ensure the following mitigations are turned \"ON\" for firefox.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Application mitigations defined in the STIG are configured by a DoD EP XML file included with the STIG package in the \"Supporting Files\" folder.

    The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> \"Use a common set of exploit protection settings\" configured to \"Enabled\" with file name and location defined under \"Options:\". It is recommended the file be in a read-only network location."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93329"
  tag rid: "SV-103417r1_rule"
  tag stig_id: "WN19-EP-000100"
  tag fix_id: "F-99575r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  # SK: Modified and copied from Windows 10 V-77205
  # Q: Condition added - If the referenced application is not installed on the system, this is NA.

  dep_script = <<-EOH
  $convert_json = Get-ProcessMitigation -Name firefox.exe | ConvertTo-Json
  $convert_out_json = ConvertFrom-Json -InputObject $convert_json
  $select_object_dep_enable = $convert_out_json.Dep | Select Enable
  $result_dep_enable = $select_object_dep_enable.Enable
  write-output $result_dep_enable
  EOH

  aslr_bottomup_script = <<-EOH
  $convert_json = Get-ProcessMitigation -Name firefox.exe | ConvertTo-Json
  $convert_out_json = ConvertFrom-Json -InputObject $convert_json
  $select_object_aslr_bottomup = $convert_out_json.Aslr | Select BottomUp
  $result_aslr_bottomup = $select_object_aslr_bottomup.BottomUp
  write-output $result_aslr_bottomup
  EOH

  aslr_forcerelocimage_script = <<-EOH
  $convert_json = Get-ProcessMitigation -Name firefox.exe | ConvertTo-Json
  $convert_out_json = ConvertFrom-Json -InputObject $convert_json
  $select_object_aslr_force_relocate_images = $convert_out_json.Aslr | Select ForceRelocateImages
  $result_aslr_force_relocate_images = $select_object_aslr_force_relocate_images.ForceRelocateImages
  write-output $result_aslr_force_relocate_images
  EOH

  if input('sensitive_system') == 'true' || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  # elsif registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId < '1709'
  #   impact 0.0
  #   describe 'This STIG does not apply to Prior Versions before 1709.' do
  #     skip 'This STIG does not apply to Prior Versions before 1709.'
  #   end
  else
    describe 'DEP is required to be enabled on FireFox' do
      subject { powershell(dep_script).strip }
      it { should_not eq '2' }
    end
    describe 'ALSR BottomUp is required to be enabled on FireFox' do
      subject { powershell(aslr_bottomup_script).strip }
      it { should_not eq '2' }
    end
    describe 'ASLR Force Relocate Image is required to be enabled on FireFox' do
      subject { powershell(aslr_forcerelocimage_script).strip }
      it { should_not eq '2' }
    end
  end
end

