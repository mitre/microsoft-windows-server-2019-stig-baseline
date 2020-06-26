# encoding: UTF-8

control "V-93309" do
  title "Windows Server 2019 default permissions of global system objects must be strengthened."
  desc  "Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default Discretionary Access Control List (DACL) that specifies who can access the objects with what permissions. When this policy is enabled, the default DACL is stronger, allowing non-administrative users to read shared objects but not to modify shared objects they did not create."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\

    Value Name: ProtectionMode

    Value Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)\" to \"Enabled\"."
  impact 0.3
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93309"
  tag rid: "SV-103397r1_rule"
  tag stig_id: "WN19-SO-000370"
  tag fix_id: "F-99555r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should cmp == 1 }
  end
end