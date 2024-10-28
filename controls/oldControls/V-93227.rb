# encoding: UTF-8

control "V-93227" do
  title "Windows Server 2019 must have orphaned security identifiers (SIDs)
removed from user rights."
  desc  "Accounts or groups given rights on a system may show up as unresolved
SIDs for various reasons including deletion of the accounts or groups.  If the
account or group objects are reanimated, there is a potential they may still
have rights no longer intended.  Valid domain accounts or groups may also show
up as unresolved SIDs if a connection to the domain cannot be established for
some reason."
  desc  "rationale", ""
  desc  'check', "Review the effective User Rights setting in Local Group Policy Editor.
    Run \"gpedit.msc\".

    Navigate to Local Computer Policy >> Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment.

    Review each User Right listed for any unresolved SIDs to determine whether
they are valid, such as due to being temporarily disconnected from the domain.
(Unresolved SIDs have the format that begins with \"*S-1-\".)

    If any unresolved SIDs exist and are not for currently valid accounts or
groups, this is a finding.

    For server core installations, run the following command:

    Secedit /export /areas USER_RIGHTS /cfg c:\\path\\UserRights.txt

    The results in the file identify user right assignments by SID instead of
group name. Review the SIDs for unidentified ones. A list of typical SIDs \\
Groups is below, search Microsoft for articles on well-known SIDs for others.

    If any unresolved SIDs exist and are not for currently valid accounts or
groups, this is a finding.

    SID - Group
    S-1-5-11 - Authenticated Users
    S-1-5-113 - Local account
    S-1-5-114 - Local account and member of Administrators group
    S-1-5-19 - Local Service
    S-1-5-20 - Network Service
    S-1-5-32-544 - Administrators
    S-1-5-32-546 - Guests
    S-1-5-6 - Service
    S-1-5-9 - Enterprise Domain Controllers
    S-1-5-domain-512 - Domain Admins
    S-1-5-root domain-519 - Enterprise Admins
    S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420 - NT
Service\\WdiServiceHost"
  desc  'fix', "Remove any unresolved SIDs found in User Rights assignments and
determined to not be for currently valid accounts or groups by removing the
accounts or groups from the appropriate group policy."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-93227'
  tag 'rid': 'SV-103315r1_rule'
  tag 'stig_id': 'WN19-00-000450'
  tag 'fix_id': 'F-99473r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]

  describe "A manual review is required to ensure orphaned security identifiers (SIDs) are removed from user rights on Windows Server 2019" do
    skip 'A manual review is required to ensure orphaned security identifiers (SIDs) are removed from user rights on Windows Server 2019'
  end
 end

