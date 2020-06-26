# encoding: UTF-8

control "V-93331" do
  title "Windows Server 2019 Exploit Protection mitigations must be configured for FLTLDR.EXE."
  desc  "Exploit protection provides a means of enabling additional mitigations against potential threats at the system and application level. Without these additional application protections, Windows may be subject to various exploits."
  desc  "rationale", ""
  desc  "check", "If the referenced application is not installed on the system, this is NA.

    This is applicable to unclassified systems, for other systems this is NA.
    Run \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Get-ProcessMitigation -Name FLTLDR.EXE\".
    (Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured.)

    If the following mitigations do not have a status of \"ON\", this is a finding:

    DEP:
    Enable: ON

    ImageLoad:
    BlockRemoteImageLoads: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    Child Process:
    DisallowChildProcessCreation: ON

    The PowerShell command produces a list of mitigations; only those with a required status of \"ON\" are listed here."
  desc  "fix", "Ensure the following mitigations are turned \"ON\" for FLTLDR.EXE:

    DEP:
    Enable: ON

    ImageLoad:
    BlockRemoteImageLoads: ON

    Payload:
    EnableExportAddressFilter: ON
    EnableExportAddressFilterPlus: ON
    EnableImportAddressFilter: ON
    EnableRopStackPivot: ON
    EnableRopCallerCheck: ON
    EnableRopSimExec: ON

    Child Process:
    DisallowChildProcessCreation: ON

    Application mitigations defined in the STIG are configured by a DoD EP XML file included with the STIG package in the \"Supporting Files\" folder.

    The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> \"Use a common set of exploit protection settings\" configured to \"Enabled\" with file name and location defined under \"Options:\".  It is recommended the file be in a read-only network location."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93331"
  tag rid: "SV-103419r1_rule"
  tag stig_id: "WN19-EP-000110"
  tag fix_id: "F-99577r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  fltldr = json({ command: "Get-ProcessMitigation -Name FLTLDR.EXE | ConvertTo-Json" }).params

  if input('sensitive_system') == true || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  elsif fltldr.empty?
    impact 0.0
    describe 'The referenced application is not installed on the system, this is NA.' do
      skip 'The referenced application is not installed on the system, this is NA.'
    end
  else
    describe "Exploit Protection: the following mitigations must be set to 'ON' for FLTLDR.EXE" do
      subject { fltldr }
      its(['Dep','Enable']) { should eq 1 }
      its(['ImageLoad','BlockRemoteImageLoads']) { should eq 1 }
      its(['Payload','EnableExportAddressFilter']) { should eq 1 }
      its(['Payload','EnableExportAddressFilterPlus']) { should eq 1 }
      its(['Payload','EnableImportAddressFilter']) { should eq 1 }
      its(['Payload','EnableRopStackPivot']) { should eq 1 }
      its(['Payload','EnableRopCallerCheck']) { should eq 1 }
      its(['Payload','EnableRopSimExec']) { should eq 1 }
      its(['ChildProcess','DisallowChildProcessCreation']) { should eq 1 }
    end
  end
end