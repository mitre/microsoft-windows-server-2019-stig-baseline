# encoding: UTF-8

control "V-93069" do
  title "Windows Server 2019 Generate security audits user right must only be assigned to Local Service and Network Service."
  desc  "Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
    The \"Generate security audits\" user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined."
  desc  "rationale", ""
  desc  'check', "Verify the effective setting in Local Group Policy Editor.
    Run \"gpedit.msc\".
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.
    If any accounts or groups other than the following are granted the \"Generate security audits\" user right, this is a finding:
    - Local Service
    - Network Service

    For server core installations, run the following command:
    Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt
    Review the text file.
    If any SIDs other than the following are granted the \"SeAuditPrivilege\" user right, this is a finding:
    S-1-5-19 (Local Service)
    S-1-5-20 (Network Service)

    If an application requires this user right, this would not be a finding.
    Vendor documentation must support the requirement for having the user right.
    The requirement must be documented with the ISSO.
    The application account must meet requirements for application account passwords, such as length (WN19-00-000050) and required frequency of changes (WN19-00-000060)."
  desc  'fix', "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> \"Generate security audits\" to include only the following accounts or groups:
    - Local Service
    - Network Service"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000324-GPOS-00125'
  tag 'gid': 'V-93069'
  tag 'rid': 'SV-103157r1_rule'
  tag 'stig_id': 'WN19-UR-000120'
  tag 'fix_id': 'F-99315r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]

  active_audit_privilege_users = security_policy.SeAuditPrivilege.entries
  allowed_audit_privilege_users = input("allowed_audit_privilege_users")
  disallowed_audit_privilege_users = input("disallowed_audit_privilege_users")
  unauthorized_users = []
  os_type = command('Test-Path "$env:windir\explorer.exe"').stdout.strip

  if os_type == 'False'
    describe 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt' do
      skip 'This system is a Server Core Installation, and a manual check will need to be performed with command Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt'
    end
  else
    active_audit_privilege_users.each do |user|
      next if allowed_audit_privilege_users.include?(user)
      unauthorized_users << user
    end
    disallowed_audit_privilege_users.each do |user|
      unless disallowed_audit_privilege_users == [nil] || unauthorized_users.include?(user)
        unauthorized_users << user
      end
    end
    describe "Security Audit Generation Privilege must be limited to" do
      it "Authorized SIDs: #{allowed_audit_privilege_users}" do
        failure_message = "Unauthorized SIDs: #{unauthorized_users}"
        expect(unauthorized_users).to be_empty, failure_message
      end
    end
  end
end