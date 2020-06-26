# encoding: UTF-8

control "V-93271" do
  title "Windows Server 2019 directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access."
  desc  "To the extent that anonymous access to directory data (outside the root DSE) is permitted, read access control of the data is effectively disabled. If other means of controlling access (such as network restrictions) are compromised, there may be nothing else to protect the confidentiality of sensitive directory data."
  desc  "rationale", ""
  desc  "check", "This applies to domain controllers. It is NA for other systems.

    Open \"Command Prompt\" (not elevated).
    Run \"ldp.exe\".
    From the \"Connection menu\", select \"Bind\".
    Clear the User, Password, and Domain fields.
    Select \"Simple bind\" for the Bind type and click \"OK\".
    Confirmation of anonymous access will be displayed at the end:
    res = ldap_simple_bind_s
    Authenticated as: 'NT AUTHORITY\\ANONYMOUS LOGON'
    From the \"Browse\" menu, select \"Search\".
    In the Search dialog, enter the DN of the domain naming context (generally something like \"dc=disaost,dc=mil\") in the Base DN field.
    Clear the Attributes field and select \"Run\".
    Error messages should display related to Bind and user not authenticated.

    If attribute data is displayed, anonymous access is enabled to the domain naming context and this is a finding.
    The following network controls allow the finding severity to be downgraded to a CAT II since these measures lower the risk associated with anonymous access.
    Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions.
    Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified by domain (.mil) or IP address."
  desc  "fix", "Configure directory data (outside the root DSE) of a non-public directory to prevent anonymous access.
    For AD, there are multiple configuration items that could enable anonymous access.
    Changing the access permissions on the domain naming context object (from the secure defaults) could enable anonymous access. If the check procedures indicate this is the cause, the process that was used to change the permissions should be reversed. This could have been through the Windows Support Tools ADSI Edit console (adsiedit.msc).
    The dsHeuristics option is used. This is addressed in check V-8555 in the AD Forest STIG."
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: "V-93271"
  tag rid: "SV-103359r1_rule"
  tag stig_id: "WN19-DC-000150"
  tag fix_id: "F-99517r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe 'Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.' do
      skip 'Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access is a manual control'
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is NA' do
      skip 'This system is not a domain controller, therefore this control is NA'
    end
  end
end