# encoding: UTF-8

control "V-93493" do
  title "Windows Server 2019 users must be required to enter a password to access private keys stored on the computer."
  desc  "If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.
    The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

    If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

    Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys."
  desc  "rationale", ""
  desc  "check", "If the following registry value does not exist or is not configured as specified, this is a finding:

    Registry Hive:  HKEY_LOCAL_MACHINE
    Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\

    Value Name:  ForceKeyProtection

    Type:  REG_DWORD
    Value:  0x00000002 (2)"
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"System cryptography: Force strong key protection for user keys stored on the computer\" to \"User must enter a password each time they use a key\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000067-GPOS-00035"
  tag gid: "V-93493"
  tag rid: "SV-103579r1_rule"
  tag stig_id: "WN19-SO-000350"
  tag fix_id: "F-99737r1_fix"
  tag cci: ["CCI-000186"]
  tag nist: ["IA-5 (2) (b)", "Rev_4"]

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography') do
    it { should have_property 'ForceKeyProtection' }
    its('ForceKeyProtection') { should cmp == 2 }
  end 
end