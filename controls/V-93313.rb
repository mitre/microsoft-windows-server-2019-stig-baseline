control "V-93313" do
  title "Windows Server 2019 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on."
  desc  "Exploit protection enables mitigations against potential threats at the system and application level.  Several mitigations, including \"Data Execution Prevention (DEP)\", are enabled by default at the system level. DEP prevents code from being run from data-only memory pages. If this is turned off, Windows may be subject to various exploits."
  desc  "rationale", ""
  desc  "check", "This is applicable to unclassified systems, for other systems this is NA.

    The default configuration in Exploit Protection is \"On by default\" which meets this requirement.  The PowerShell query results for this show as \"NOTSET\".
    Run \"Windows PowerShell\" with elevated privileges (run as administrator).
    Enter \"Get-ProcessMitigation -System\".
    If the status of \"DEP: Enable\" is \"OFF\", this is a finding.

    Values that would not be a finding include:
    ON
    NOTSET (Default configuration)"
  desc  "fix", "Ensure Exploit Protection system-level mitigation, \"Data Execution Prevention (DEP)\", is turned on.  The default configuration in Exploit Protection is \"On by default\" which meets this requirement.

    Open \"Windows Defender Security Center\".
    Select \"App & browser control\".
    Select \"Exploit protection settings\".
    Under \"System settings\", configure \"Data Execution Prevention (DEP)\" to \"On by default\" or \"Use default (<On>)\".

    The STIG package includes a DoD EP XML file in the \"Supporting Files\" folder for configuring application mitigations defined in the STIG.  This can also be modified to explicitly enforce the system level requirements.  Adding the following to the XML file will explicitly turn DEP on (other system level EP requirements can be combined under <SystemConfig>):

    <SystemConfig>
      <DEP Enable=\"true\"></DEP>
    </SystemConfig>

    The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> \"Use a common set of exploit protection settings\" configured to \"Enabled\" with file name and location defined under \"Options:\". It is recommended the file be in a read-only network location."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93313"
  tag rid: "SV-103401r1_rule"
  tag stig_id: "WN19-EP-000010"
  tag fix_id: "F-99559r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  systemdep = json({ command: "Get-ProcessMitigation -System | ConvertTo-Json" }).params

  if input('sensitive_system') == true || nil
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  elsif systemdep.empty?
    describe "Exploit Protection: the following mitigation" do
      it "must be set to 'ON' for the System" do
        failure_message = "Exploit Protection is not set"
        expect(systemdep).not_to be_empty, failure_message
      end
    end
  else
    describe "Exploit Protection: the following mitigation must be set to 'ON' for the System" do
      subject { systemdep }
      its(['Dep','Enable']) { should be_between(0,1) }
    end
  end
end