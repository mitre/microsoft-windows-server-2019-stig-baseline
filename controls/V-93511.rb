# encoding: UTF-8

control "V-93511" do
  title "Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
  desc  "This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

    Value Name: Enabled

    Value Type: REG_DWORD
    Value: 0x00000001 (1)

    Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms. Both the browser and web server must be configured to use TLS; otherwise. the browser will not be able to connect to a secure site."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing\" to \"Enabled\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000478-GPOS-00223"
  tag gid: "V-93511"
  tag rid: "SV-103597r1_rule"
  tag stig_id: "WN19-SO-000360"
  tag fix_id: "F-99755r1_fix"
  tag cci: ["CCI-002450"]
  tag nist: ["SC-13", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp == 1 }
  end
end