# encoding: UTF-8

control "V-93289" do
  title "Windows Server 2019 must not allow anonymous SID/Name translation."
  desc  "Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations."
  desc  "rationale", ""
  desc  "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

    If the value for \"Network access: Allow anonymous SID/Name translation\" is not set to \"Disabled\", this is a finding."
  desc  "fix", "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> \"Network access: Allow anonymous SID/Name translation\" to \"Disabled\"."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93289"
  tag rid: "SV-103377r1_rule"
  tag stig_id: "WN19-SO-000210"
  tag fix_id: "F-99535r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end