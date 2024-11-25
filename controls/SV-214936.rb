control 'SV-214936' do
  title 'Windows Server 2019 must have a host-based firewall installed and enabled.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-214936'
  tag rid: 'SV-214936r991589_rule'
  tag stig_id: 'WN19-00-000280'
  tag fix_id: 'F-16134r356141_fix'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']

  query_domain = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Domain' } | Select Enabled | ConvertTo-Json" }).params
  query_private = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Private' } | Select Enabled | ConvertTo-Json" }).params
  query_public = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Public' } | Select Enabled | ConvertTo-Json" }).params

  describe.one do
    describe 'Windows Firewall should be Enabled' do
      subject { query_public['Enabled'] }
      it 'The Public host-based firewall' do
        failure_message = 'is not Enabled'
        expect(subject).to eql(1), failure_message
      end
    end
    describe 'Windows Firewall should be Enabled' do
      subject { query_private['Enabled'] }
      it 'The Private host-based firewall' do
        failure_message = 'is not enabled'
        expect(subject).to eql(1), failure_message
      end
    end
    describe 'Windows Firewall should be Enabled' do
      subject { query_domain['Enabled'] }
      it 'The Domain host-based firewall' do
        failure_message = 'is not Enabled'
        expect(subject).to eql(1), failure_message
      end
    end
  end
end
