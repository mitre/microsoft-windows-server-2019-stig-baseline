# encoding: UTF-8

control "V-92971" do
  title "Windows Server 2019 Remote Desktop Services must require secure Remote
Procedure Call (RPC) communications."
  desc  "Allowing unsecure RPC communication exposes the system to
man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle
attack occurs when an intruder captures packets between a client and server and
modifies them before allowing the packets to be exchanged. Usually the attacker
will modify the information in the packets in an attempt to cause either the
client or server to reveal sensitive information."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal
Services\\

    Value Name: fEncryptRPCTraffic

    Type: REG_DWORD
    Value: 0x00000001 (1)"
  desc  'fix', "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Remote Desktop Services >>
Remote Desktop Session Host >> Security >> \"Require secure RPC communication\"
to \"Enabled\"."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000033-GPOS-00014'
  tag 'satisfies': ["SRG-OS-000033-GPOS-00014", "SRG-OS-000250-GPOS-00093"]
  tag 'gid': 'V-92971'
  tag 'rid': 'SV-103059r1_rule'
  tag 'stig_id': 'WN19-CC-000370'
  tag 'fix_id': 'F-99217r1_fix'
  tag 'cci': ["CCI-000068", "CCI-001453"]
  tag 'nist': ["AC-17 (2)", "AC-17 (2)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property "fEncryptRPCTraffic"}
    its("fEncryptRPCTraffic") { should cmp 1 }
  end
end

