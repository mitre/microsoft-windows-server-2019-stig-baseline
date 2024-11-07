control 'SV-205650' do
  title 'Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.'
  desc 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to unclassified systems.'
  desc 'check', 'This is applicable to unclassified systems. It is NA for others.

Open "PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM                                                                                                                                                                                                                                                     
Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.

For each certificate with "US DoD CCEB Interoperability Root CA ..." under "Issued By":

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
NotAfter: 7/18/2025 9:56:22 AM'
  desc 'fix', 'Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.

Issued To - Issued By - Thumbprint

DoD Root CA 3 - US DoD CCEB Interoperability Root CA 2 - 9B74964506C7ED9138070D08D5F8B969866560C8

Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.

The FBCA Cross-Certificate Remover Tool and User Guide are available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag gid: 'V-205650'
  tag rid: 'SV-205650r958448_rule'
  tag stig_id: 'WN19-PK-000030'
  tag fix_id: 'F-5915r890529_fix'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (a)', 'SC-23 (5)', 'IA-5 (2) (b) (1)']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    dod_cceb_certificates = JSON.parse(input('dod_cceb_certificates').to_json)
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\\\disallowed | Where {$_.Issuer -Like "*CCEB Interoperability*"} | Select Subject, Issuer, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' })

    describe 'Verify the DoD CCEB CA certificates are installed as Untrusted Certificate.' do
      subject { query.params }
      it { should be_in dod_cceb_certificates }
    end

    unless query.empty?
      case query
      when Hash
        query.each do |key, value|
          if key == "NotAfter"
            cert_date = Date.parse(value)
            describe cert_date do
              it { should be >= Date.today }
            end
          end
        end
      when Array
        query.each do |certs|
          certs.each do |key, value|
            if key == "NotAfter"
              cert_date = Date.parse(value)
              describe cert_date do
                it { should be >= Date.today }
              end
            end
          end
        end
      end
    end
  end
end
