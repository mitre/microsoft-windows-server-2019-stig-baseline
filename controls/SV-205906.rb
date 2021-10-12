# encoding: UTF-8

control 'SV-205906' do
  title "Windows Server 2019 must limit the caching of logon credentials to
four or less on domain-joined member servers."
  desc  "The default Windows configuration caches the last logon credentials
for users who log on interactively to a system. This feature is provided for
system availability reasons, such as the user's machine being disconnected from
the network or domain controllers being unavailable. Even though the credential
cache is well protected, if a system is attacked, an unauthorized individual
may isolate the password to a domain user account using a password-cracking
program and gain access to the domain."
  desc  'rationale', ''
  desc  'check', "
    This applies to member servers. For domain controllers and standalone
systems, this is NA.

    If the following registry value does not exist or is not configured as
specified, this is a finding:

    Registry Hive:  HKEY_LOCAL_MACHINE
    Registry Path:  \\SOFTWARE\\Microsoft\\Windows
NT\\CurrentVersion\\Winlogon\\

    Value Name:  CachedLogonsCount

    Value Type:  REG_SZ
    Value:  4 (or less)
  "
  desc  'fix', "Configure the policy value for Computer Configuration >>
Windows Settings >> Security Settings >> Local Policies >> Security Options >>
\"Interactive Logon: Number of previous logons to cache (in case Domain
Controller is not available)\" to \"4\" logons or less."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-205906'
  tag rid: 'SV-205906r569188_rule'
  tag stig_id: 'WN19-MS-000050'
  tag fix_id: 'F-6171r356081_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['SV-103363', 'V-93275']
  tag nist: ['CM-6 b']

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '3'
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
      it { should have_property 'CachedLogonsCount' }
      its('CachedLogonsCount') { should cmp <= 4 }
    end
  else
    impact 0.0
    describe 'This requirement is only applicable to member servers' do
      skip 'This control is NA as the requirement is only applicable to member servers'
    end
  end

end

