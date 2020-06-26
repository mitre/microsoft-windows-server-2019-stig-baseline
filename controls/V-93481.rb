# encoding: UTF-8

control "V-93481" do
  title "Windows Server 2019 domain controllers must have a PKI server certificate."
  desc  "Domain controllers are part of the chain of trust for PKI authentications. Without the appropriate certificate, the authenticity of the domain controller cannot be verified. Domain controllers must have a server certificate to establish authenticity as part of PKI authentications in the domain."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.
    Run \"MMC\".
    Select \"Add/Remove Snap-in\" from the \"File\" menu.
    Select \"Certificates\" in the left pane and click the \"Add >\" button.
    Select \"Computer Account\" and click \"Next\".
    Select the appropriate option for \"Select the computer you want this snap-in to manage\" and click \"Finish\".
    Click \"OK\".
    Select and expand the Certificates (Local Computer) entry in the left pane.
    Select and expand the Personal entry in the left pane.
    Select the Certificates entry in the left pane.
    If no certificate for the domain controller exists in the right pane, this is a finding."
  desc  "fix", "Obtain a server certificate for the domain controller."
  impact 0.5
  tag severity: nil
  tag gtitle: "SRG-OS-000066-GPOS-00034"
  tag gid: "V-93481"
  tag rid: "SV-103567r1_rule"
  tag stig_id: "WN19-DC-000280"
  tag fix_id: "F-99725r1_fix"
  tag cci: ["CCI-000185"]
  tag nist: ["IA-5 (2) (a)", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    certs = command("Get-ChildItem -Path Cert:\\LocalMachine\\My | ConvertTo-JSON").stdout
    describe 'Verify that the domain controller has a PKI server certificate.' do
      subject { certs }
      it { should_not be_empty }
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end