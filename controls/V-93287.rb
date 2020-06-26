# encoding: UTF-8

control "V-93287" do
  title "Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation."
  desc  "Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

    Value Name: scremoveoption

    Value Type: REG_SZ
    Value: 1 (Lock Workstation) or 2 (Force Logoff)

    If configuring this on servers causes issues, such as terminating users' remote sessions, and the organization has a policy in place that any other sessions on the servers, such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the ISSO."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Interactive logon: Smart card removal behavior\" to \"Lock Workstation\" or \"Force Logoff\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93287"
  tag rid: "SV-103375r1_rule"
  tag stig_id: "WN19-SO-000150"
  tag fix_id: "F-99533r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'scremoveoption' }
    its('scremoveoption') { should be_between("1", "2") }
  end
end