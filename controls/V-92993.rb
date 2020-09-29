# encoding: UTF-8

control "V-92993" do
  title "Windows Server 2019 non-administrative accounts or groups must only
have print permissions on printer shares."
  desc  "Windows shares are a means by which files, folders, printers, and
other resources can be published for network users to access. Improper
configuration can permit access to devices and data beyond a user's need."
  desc  "rationale", ""
  desc  'check', "Open \"Printers & scanners\" in \"Settings\".

    If there are no printers configured, this is NA. (Exclude Microsoft Print
to PDF and Microsoft XPS Document Writer, which do not support sharing.)

    For each printer:

    Select the printer and \"Manage\".

    Select \"Printer Properties\".

    Select the \"Sharing\" tab.

    If \"Share this printer\" is checked, select the \"Security\" tab.

    If any standard user accounts or groups have permissions other than
\"Print\", this is a finding.

    The default is for the \"Everyone\" group to be given \"Print\" permission.

    \"All APPLICATION PACKAGES\" and \"CREATOR OWNER\" are not standard user
accounts."
  desc  'fix', "Configure the permissions on shared printers to restrict
standard users to only have Print permissions."
  impact 0.3
  tag 'severity': nil
  tag 'gtitle': 'SRG-OS-000080-GPOS-00048'
  tag 'gid': 'V-92993'
  tag 'rid': 'SV-103081r1_rule'
  tag 'stig_id': 'WN19-00-000180'
  tag 'fix_id': 'F-99239r1_fix'
  tag 'cci': ["CCI-000213"]
  tag 'nist': ["AC-3", "Rev_4"]
  
    describe "A manual review is required to verify that Non Administrative user accounts or groups only have print
    permissions on printer shares" do
      skip 'A manual review is required to verify that Non Administrative user accounts or groups only have print
    permissions on printer shares'
    end

end

