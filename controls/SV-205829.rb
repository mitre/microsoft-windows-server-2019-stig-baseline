# encoding: UTF-8

control 'SV-205829' do
  title "Windows Server 2019 must implement protection methods such as TLS,
encrypted VPNs, or IPsec if the data owner has a strict requirement for
ensuring data integrity and confidentiality is maintained at every step of the
data transfer and handling process."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, for example, during aggregation,
at protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    Ensuring the confidentiality of transmitted information requires the
operating system to take measures in preparing information for transmission.
This can be accomplished via access control and encryption.

    Use of this requirement will be limited to situations where the data owner
has a strict requirement for ensuring data integrity and confidentiality is
maintained at every step of the data transfer and handling process. When
transmitting data, operating systems need to support transmission protection
mechanisms such as TLS, encrypted VPNs, or IPsec."
  desc  'rationale', ''
  desc  'check', "
    If the data owner has a strict requirement for ensuring data integrity and
confidentiality is maintained at every step of the data transfer and handling
process, verify protection methods such as TLS, encrypted VPNs, or IPsec have
been implemented.

    If protection methods have not been implemented, this is a finding.
  "
  desc  'fix', "Configure protection methods such as TLS, encrypted VPNs, or
IPsec when the data owner has a strict requirement for ensuring data integrity
and confidentiality is maintained at every step of the data transfer and
handling process."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag satisfies: ['SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-205829'
  tag rid: 'SV-205829r569188_rule'
  tag stig_id: 'WN19-00-000260'
  tag fix_id: 'F-6094r355850_fix'
  tag cci: ['CCI-002422', 'CCI-002420']
  tag legacy: ['V-93543', 'SV-103629']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']

  describe "A manual review is required to ensure protection methods such as TLS, encrypted VPNs, or IPSEC are
  implemented if the data owner has a strict requirement for ensuring data
  integrity and confidentiality is maintained at every step of the data transfer
  and handling process." do
    skip "A manual review is required to ensure protection methods such as TLS, encrypted VPNs, or IPSEC are
      implemented if the data owner has a strict requirement for ensuring data
      integrity and confidentiality is maintained at every step of the data transfer
      and handling process."
  end

end

