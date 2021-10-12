# encoding: UTF-8

control 'SV-205632' do
  title "Windows Server 2019 title for legal banner dialog box must be
configured with the appropriate text."
  desc  "Failure to display the logon banner prior to a logon attempt will
negate legal proceedings resulting from unauthorized access to system resources."
  desc  'rationale', ''
  desc  'check', "
    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

    Value Name: LegalNoticeCaption

    Value Type: REG_SZ
    Value: See message title options below

    \"DoD Notice and Consent Banner\", \"US Department of Defense Warning
Statement\", or an organization-defined equivalent.

    If an organization-defined title is used, it can in no case contravene or
modify the language of the banner text required in WN19-SO-000150.

    Automated tools may only search for the titles defined above. If an
organization-defined title is used, a manual review will be required.
  "
  desc  'fix', "
    Configure the policy value for Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> Security Options >> \"Interactive
Logon: Message title for users attempting to log on\" to \"DoD Notice and
Consent Banner\", \"US Department of Defense Warning Statement\", or an
organization-defined equivalent.

    If an organization-defined title is used, it can in no case contravene or
modify the language of the message text required in WN19-SO-000150.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-205632'
  tag rid: 'SV-205632r569188_rule'
  tag stig_id: 'WN19-SO-000140'
  tag fix_id: 'F-5897r354815_fix'
  tag cci: ['CCI-001388', 'CCI-001386', 'CCI-001387', 'CCI-001384', 'CCI-001385', 'CCI-000048']
  tag legacy: ['SV-103237', 'V-93149']
  tag nist: ['AC-8 c 3', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 1', 'AC-8 c 2', "AC-8a"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LegalNoticeCaption' }
    its('LegalNoticeCaption') { should be_in input('LegalNoticeCaption') }
  end

end

