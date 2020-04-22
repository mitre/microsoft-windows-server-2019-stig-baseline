# encoding: UTF-8

control "V-93029" do
  title "Windows Server 2019 permissions on the Active Directory data files
must only allow System and Administrators access."
  desc  "Improper access permissions for directory data-related files could
allow unauthorized users to read, modify, or delete directory data or audit
trails."
  desc  "rationale", ""
  desc  "check", "
    This applies to domain controllers. It is NA for other systems.

    Run \"Regedit\".

    Navigate to
\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\".

    Note the directory locations in the values for:

    Database log files path
    DSA Database file

    By default, they will be \\Windows\\NTDS.

    If the locations are different, the following will need to be run for each.

    Open \"Command Prompt (Admin)\".

    Navigate to the NTDS directory (\\Windows\\NTDS by default).

    Run \"icacls *.*\".

    If the permissions on each file are not as restrictive as the following,
this is a finding:

    NT AUTHORITY\\SYSTEM:(I)(F)
    BUILTIN\\Administrators:(I)(F)

    (I) - permission inherited from parent container
    (F) - full access
  "
  desc  "fix", "
    Maintain the permissions on NTDS database and log files as follows:

    NT AUTHORITY\\SYSTEM:(I)(F)
    BUILTIN\\Administrators:(I)(F)

    (I) - permission inherited from parent container
    (F) - full access
  "
  impact 0.7
  tag severity: nil
  tag gtitle: "SRG-OS-000324-GPOS-00125"
  tag gid: "V-93029"
  tag rid: "SV-103117r1_rule"
  tag stig_id: "WN19-DC-000070"
  tag fix_id: "F-99275r1_fix"
  tag cci: ["CCI-002235"]
  tag nist: ["AC-6 (10)", "Rev_4"]
end

