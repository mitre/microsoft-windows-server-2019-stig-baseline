# encoding: UTF-8

control "V-93245" do
  title "Windows Server 2019 virtualization-based security must be enabled with
the platform security level configured to Secure Boot or Secure Boot with DMA
Protection."
  desc  "Virtualization Based Security (VBS) provides the platform for the
additional security features Credential Guard and virtualization-based
protection of code integrity. Secure Boot is the minimum security level, with
DMA protection providing additional memory protection. DMA Protection requires
a CPU that supports input/output memory management unit (IOMMU)."
  desc  "rationale", ""
  desc  'check', "For standalone systems, this is NA.

    Current hardware and virtual environments may not support
virtualization-based security features, including Credential Guard, due to
specific supporting requirements, including a TPM, UEFI with Secure Boot, and
the capability to run the Hyper-V feature within a virtual machine.

    Open \"PowerShell\" with elevated privileges (run as administrator).

    Enter the following:

    \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace
root\\Microsoft\\Windows\\DeviceGuard\"

    If \"RequiredSecurityProperties\" does not include a value of \"2\"
indicating \"Secure Boot\" (e.g., \"{1, 2}\"), this is a finding.

    If \"Secure Boot and DMA Protection\" is configured, \"3\" will also be
displayed in the results (e.g., \"{1, 2, 3}\").

    If \"VirtualizationBasedSecurityStatus\" is not a value of \"2\" indicating
\"Running\", this is a finding.

    Alternately:

    Run \"System Information\".

    Under \"System Summary\", verify the following:

    If \"Device Guard Virtualization based security\" does not display
\"Running\", this is a finding.

    If \"Device Guard Required Security Properties\" does not display \"Base
Virtualization Support, Secure Boot\", this is a finding.

    If \"Secure Boot and DMA Protection\" is configured, \"DMA Protection\"
will also be displayed (e.g., \"Base Virtualization Support, Secure Boot, DMA
Protection\").

    The policy settings referenced in the Fix section will configure the
following registry values. However, due to hardware requirements, the registry
values alone do not ensure proper function.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

    Value Name: EnableVirtualizationBasedSecurity
    Value Type: REG_DWORD
    Value: 0x00000001 (1)

    Value Name: RequirePlatformSecurityFeatures
    Value Type: REG_DWORD
    Value: 0x00000001 (1) (Secure Boot only) or 0x00000003 (3) (Secure Boot and
DMA Protection)

    A Microsoft TechNet article on Credential Guard, including system
requirement details, can be found at the following link:

    https://technet.microsoft.com/itpro/windows/keep-secure/credential-guard"
  desc  'fix', "Configure the policy value for Computer Configuration >> Administrative
Templates >> System >> Device Guard >> \"Turn On Virtualization Based
Security\" to \"Enabled\" with \"Secure Boot\" or \"Secure Boot and DMA
Protection\" selected.

    A Microsoft TechNet article on Credential Guard, including system
requirement details, can be found at the following link:

    https://technet.microsoft.com/itpro/windows/keep-secure/credential-guard"
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93245'
  tag 'rid': 'SV-103333r1_rule'
  tag 'stig_id': 'WN19-CC-000110'
  tag 'fix_id': 'F-99491r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip
   if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
   else
     describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
      it { should have_property 'EnableVirtualizationBasedSecurity' }
      its('EnableVirtualizationBasedSecurity') { should cmp 1 }
     end
     describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should have_property 'RequirePlatformSecurityFeatures' }
        its('RequirePlatformSecurityFeatures') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should have_property 'RequirePlatformSecurityFeatures' }
        its('RequirePlatformSecurityFeatures') { should cmp 3 }
      end
     end
    end
end

