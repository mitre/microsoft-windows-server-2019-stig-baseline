# encoding: UTF-8

control "V-93335" do
  title "Windows Server 2019 Exploit Protection mitigations must be configured for iexplore.exe."
  desc  "Exploit protection provides a means of enabling additional mitigations against potential threats at the system and application level. Without these additional application protections, Windows may be subject to various exploits."
  desc  "rationale", ""
  desc  "check", "If the referenced application is not installed on the system, this is NA.

    This is applicable to unclassified systems, for other systems this is NA.
    Run \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Get-ProcessMitigation -Name iexplore.exe\".
    (Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured.)

    If the following mitigations do not have a status of \"ON\", this is a finding:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    The PowerShell command produces a list of mitigations; only those with a required status of \"ON\" are listed here."
  desc  "fix", "Ensure the following mitigations are turned \"ON\" for iexplore.exe:

    DEP:
    Enable: ON

    ASLR:
    BottomUp: ON
    ForceRelocateImages: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    Application mitigations defined in the STIG are configured by a DoD EP XML file included with the STIG package in the \"Supporting Files\" folder.

    The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> \"Use a common set of exploit protection settings\" configured to \"Enabled\" with file name and location defined under \"Options:\".  It is recommended the file be in a read-only network location."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93335"
  tag rid: "SV-103423r1_rule"
  tag stig_id: "WN19-EP-000130"
  tag fix_id: "F-99581r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  # SK: Modified and copied from Windows 10 V-77217
  # Q: Condition added - If the referenced application is not installed on the system, this is NA.
  # Q: Test pending

  dep_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_dep_enable = $convert_out_json.Dep | Select Enable
    $result_dep_enable = $select_object_dep_enable.Enable
    write-output $result_dep_enable
  EOH

  aslr_bottomup_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe| ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_aslr_bottomup = $convert_out_json.Aslr | Select BottomUp
    $result_aslr_bottomup = $select_object_aslr_bottomup.BottomUp
    write-output $result_aslr_bottomup
  EOH

  aslr_forcerelocimage_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_aslr_force_relocate_images = $convert_out_json.Aslr | Select ForceRelocateImages
    $result_aslr_force_relocate_images = $select_object_aslr_force_relocate_images.ForceRelocateImages
    write-output $result_aslr_force_relocate_images
  EOH

  payload_enexpaddrfil_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enexportaddrfil = $convert_out_json.Payload | Select EnableExportAddressFilter
    $result_payload_enexportaddrfil = $select_object_payload_enexportaddrfil.EnableExportAddressFilter
    write-output $result_payload_enexportaddrfil
  EOH

  payload_enexpaddrfilplus_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enexpaddrfilplus = $convert_out_json.Payload | Select EnableExportAddressFilterPlus
    $result_payload_enexpaddrfilplus = $select_object_payload_enexpaddrfilplus.EnableExportAddressFilterPlus
    write-output $result_payload_enexpaddrfilplus
  EOH

  payload_enimpaddrfil_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enimpaddrfil = $convert_out_json.Payload | Select EnableImportAddressFilter
    $result_payload_enimpaddrfil = $select_object_payload_enimpaddrfil.EnableImportAddressFilter
    write-output $result_payload_enimpaddrfil
  EOH

  payload_enropstacpiv_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enropstacpiv = $convert_out_json.Payload | Select EnableRopStackPivot
    $result_payload_enropstacpiv = $select_object_payload_enropstacpiv.EnableRopStackPivot
    write-output $result_payload_enropstacpiv
  EOH

  payload_enropcalleche_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enropcalleche = $convert_out_json.Payload | Select EnableRopCallerCheck
    $result_payload_enropcalleche = $select_object_payload_enropcalleche.EnableRopCallerCheck
    write-output $result_payload_enropcalleche
  EOH

  payload_enropsimexec_script = <<~EOH
    $convert_json = Get-ProcessMitigation -Name iexplore.exe | ConvertTo-Json
    $convert_out_json = ConvertFrom-Json -InputObject $convert_json
    $select_object_payload_enropsimexec = $convert_out_json.Payload | Select EnableRopSimExec
    $result_payload_enropsimexec = $select_object_payload_enropsimexec.EnableRopSimExec
    write-output $result_payload_enropsimexec
  EOH

  if input('sensitive_system') == true || nil
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
    describe 'DEP is required to be enabled on Internet Explorer' do
      subject { powershell(dep_script).strip }
      it { should_not eq '2' }
    end
    describe 'ALSR BottomUp is required to be enabled on Internet Explorer' do
      subject { powershell(aslr_bottomup_script).strip }
      it { should_not eq '2' }
    end
    describe 'ASLR Force Relocate Image is required to be enabled on Internet Explorer' do
      subject { powershell(aslr_forcerelocimage_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Export Address Filter is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enexpaddrfil_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Export Address Filter Plus is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enexpaddrfilplus_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Import Address Filter is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enimpaddrfil_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Rop Stack Pivot is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enropstacpiv_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Rop Caller Check is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enropcalleche_script).strip }
      it { should_not eq '2' }
    end
    describe 'Payload Enable Rop Sim Exec is required to be enabled on Internet Explorer' do
      subject { powershell(payload_enropsimexec_script).strip }
      it { should_not eq '2' }
    end
  end

end