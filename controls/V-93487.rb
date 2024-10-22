control 'V-205648' do
  title 'Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.'
  desc 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs. The DoD root certificates will ensure that the trust chain is established for server certificates issued from the DoD CAs.'
  desc 'check', 'Certificates and thumbprints referenced below apply to unclassified systems; refer to PKE documentation for other networks.

Open "Windows PowerShell" as an administrator.

Execute the following command:

Get-ChildItem -Path Cert:Localmachine\\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 

Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
NotAfter: 12/30/2029

Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
NotAfter: 7/25/2032

Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
NotAfter: 6/14/2041

Subject: CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US 
Thumbprint: D37ECF61C0B4ED88681EF3630C4E2FC787B37AEF
NotAfter: 1/24/2053 11:36:17 AM

Alternately, use the Certificates MMC snap-in:

Run "MMC".

Select "File", "Add/Remove Snap-in".

Select "Certificates" and click "Add".

Select "Computer account" and click "Next".

Select "Local computer: (the computer this console is running on)" and click "Finish".

Click "OK".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".

For each of the DoD Root CA certificates noted below:

Right-click on the certificate and select "Open".

Select the "Details" tab.

Scroll to the bottom and select "Thumbprint".

If the DoD Root CA certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a finding.

DoD Root CA 3
Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
Valid to: Sunday, December 30, 2029

DoD Root CA 4
Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
Valid to: Sunday, July 25, 2032

DoD Root CA 5
Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
Valid to: Friday, June 14, 2041

DoD Root CA 6
Thumbprint: D37ECF61C0B4ED88681EF3630C4E2FC787B37AEFB
Valid to: Friday, January 24, 2053'
  desc 'fix', 'Install the DoD Root CA certificates:
DoD Root CA 3
DoD Root CA 4
DoD Root CA 5
DoD Root CA 6

The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files. Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag gid: 'V-205648'
  tag rid: 'SV-205648r958448_rule'
  tag stig_id: 'WN19-PK-000010'
  tag fix_id: 'F-5913r921947_fix'
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (a)', 'SC-23 (5)', 'Rev_4', 'IA-5 (2) (b) (1)']

  if input('sensitive_system') == true
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    dod_interoperability_certificates = JSON.parse(input('dod_interoperability_certificates').to_json)
    query = json({ command: 'Get-ChildItem -Path Cert:Localmachine\\root  | Where Subject -Like "*DoD*" | Select Subject, Thumbprint, @{Name=\'NotAfter\';Expression={"{0:dddd, MMMM dd, yyyy}" -f [datetime]$_.NotAfter}} | ConvertTo-Json' }).params
 
    describe 'Verify DoD Root Certificate Authority (CA) certificates are installed in the Trusted Root Store.' do
      subject { query }
      it { should be_in dod_interoperability_certificates }
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
