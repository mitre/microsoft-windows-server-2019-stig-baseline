# encoding: UTF-8

control "V-93235" do
  title "Windows Server 2019 source routing must be configured to the highest
protection level to prevent Internet Protocol (IP) source routing."
  desc  "Configuring the system to disable IP source routing protects against
spoofing."
  desc  "rationale", ""
  desc  'check', "If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

    Value Name: DisableIPSourceRouting

    Value Type: REG_DWORD
    Value: 0x00000002 (2)"
  desc  'fix', "Configure the policy value for Computer Configuration >> Administrative
Templates >> MSS (Legacy) >> \"MSS: (DisableIPSourceRouting) IP source routing
protection level (protects against packet spoofing)\" to \"Enabled\" with
\"Highest protection, source routing is completely disabled\" selected.

    This policy setting requires the installation of the MSS-Legacy custom
templates included with the STIG package. \"MSS-Legacy.admx\" and
\"MSS-Legacy.adml\" must be copied to the \\Windows\\PolicyDefinitions and
\\Windows\\PolicyDefinitions\\en-US directories respectively."
  impact 0.3
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93235'
  tag 'rid': 'SV-103323r1_rule'
  tag 'stig_id': 'WN19-CC-000040'
  tag 'fix_id': 'F-99481r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp 2}
  end
end

