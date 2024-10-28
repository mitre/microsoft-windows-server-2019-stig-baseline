# encoding: UTF-8

control "V-93229" do
  title "Windows Server 2019 systems must have Unified Extensible Firmware
Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy
BIOS."
  desc  "UEFI provides additional security features in comparison to legacy
BIOS firmware, including Secure Boot. UEFI is required to support additional
security features in Windows, including Virtualization Based Security and
Credential Guard. Systems with UEFI that are operating in \"Legacy BIOS\" mode
will not support these security features."
  desc  "rationale", ""
  desc  'check', "Some older systems may not have UEFI firmware. This is currently a CAT III;
it will be raised in severity at a future date when broad support of Windows
hardware and firmware requirements are expected to be met. Devices that have
UEFI firmware must run in \"UEFI\" mode.

    Verify the system firmware is configured to run in \"UEFI\" mode, not
\"Legacy BIOS\".

    Run \"System Information\".

    Under \"System Summary\", if \"BIOS Mode\" does not display \"UEFI\", this
is a finding."
  desc  'fix', "Configure UEFI firmware to run in \"UEFI\" mode, not \"Legacy
BIOS\" mode."
  impact 0.3
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93229'
  tag 'rid': 'SV-103317r1_rule'
  tag 'stig_id': 'WN19-00-000460'
  tag 'fix_id': 'F-99475r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  uefi_boot = json( command: 'Confirm-SecureBootUEFI | ConvertTo-Json').params
    describe 'Confirm-Secure Boot UEFI is required to be enabled on System' do
     subject { uefi_boot }
     it { should_not eq 'False' }
    end
end

