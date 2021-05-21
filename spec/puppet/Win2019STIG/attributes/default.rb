default['Win2019STIG']['XCCDF_result']['Manage'] = true

default['Win2019STIG']['powershell_package_Source'] = 'PSGallery'

# R-103049 WN19-SO-000120
default['Win2019STIG']['stigrule_103049']['Manage'] = true
default['Win2019STIG']['stigrule_103049']['Title'] = "Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."
default['Win2019STIG']['stigrule_103049']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103049']['Setting']['Interactive_logon_Machine_inactivity_limit'] = '900'

# R-103051 WN19-DC-000410
default['Win2019STIG']['stigrule_103051']['Manage'] = false
default['Win2019STIG']['stigrule_103051']['Title'] = "Windows Server 2019 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access."
default['Win2019STIG']['stigrule_103051']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103051']['Setting']['Deny_log_on_through_Remote_Desktop_Services_Identity'] = ['Guests']

# R-103053 WN19-MS-000120
default['Win2019STIG']['stigrule_103053']['Manage'] = false
default['Win2019STIG']['stigrule_103053']['Title'] = "Windows Server 2019 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems."
default['Win2019STIG']['stigrule_103053']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103053']['Setting']['Deny_log_on_through_Remote_Desktop_Services_Identity'] = ['Enterprise Admins','Domain Admins','Local account','Guests']

# R-103055 WN19-AU-000190
default['Win2019STIG']['stigrule_103055']['Manage'] = true
default['Win2019STIG']['stigrule_103055']['Title'] = "Windows Server 2019 must be configured to audit logon successes."
default['Win2019STIG']['stigrule_103055']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103055']['Setting']['Logon_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103055']['Setting']['Logon_Ensure'] = 'Present'

# R-103057 WN19-AU-000200
default['Win2019STIG']['stigrule_103057']['Manage'] = true
default['Win2019STIG']['stigrule_103057']['Title'] = "Windows Server 2019 must be configured to audit logon failures."
default['Win2019STIG']['stigrule_103057']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103057']['Setting']['Logon_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103057']['Setting']['Logon_Ensure'] = 'Present'

# R-103059 WN19-CC-000370
default['Win2019STIG']['stigrule_103059']['Manage'] = true
default['Win2019STIG']['stigrule_103059']['Title'] = "Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."
default['Win2019STIG']['stigrule_103059']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
default['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_ValueType'] = :dword
default['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_ValueData'] = '1'
default['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_Ensure'] = :create

# R-103061 WN19-CC-000380
default['Win2019STIG']['stigrule_103061']['Manage'] = true
default['Win2019STIG']['stigrule_103061']['Title'] = "Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level."
default['Win2019STIG']['stigrule_103061']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
default['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_ValueType'] = :dword
default['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_ValueData'] = '3'
default['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_Ensure'] = :create

# R-103067 WN19-AU-000100
default['Win2019STIG']['stigrule_103067']['Manage'] = true
default['Win2019STIG']['stigrule_103067']['Title'] = "Windows Server 2019 must be configured to audit Account Management - Security Group Management successes."
default['Win2019STIG']['stigrule_103067']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103067']['Setting']['Security_Group_Management_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103067']['Setting']['Security_Group_Management_Ensure'] = 'Present'

# R-103069 WN19-AU-000110
default['Win2019STIG']['stigrule_103069']['Manage'] = true
default['Win2019STIG']['stigrule_103069']['Title'] = "Windows Server 2019 must be configured to audit Account Management - User Account Management successes."
default['Win2019STIG']['stigrule_103069']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103069']['Setting']['User_Account_Management_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103069']['Setting']['User_Account_Management_Ensure'] = 'Present'

# R-103071 WN19-AU-000120
default['Win2019STIG']['stigrule_103071']['Manage'] = true
default['Win2019STIG']['stigrule_103071']['Title'] = "Windows Server 2019 must be configured to audit Account Management - User Account Management failures."
default['Win2019STIG']['stigrule_103071']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103071']['Setting']['User_Account_Management_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103071']['Setting']['User_Account_Management_Ensure'] = 'Present'

# R-103073 WN19-DC-000230
default['Win2019STIG']['stigrule_103073']['Manage'] = true
default['Win2019STIG']['stigrule_103073']['Title'] = "Windows Server 2019 must be configured to audit Account Management - Computer Account Management successes."
default['Win2019STIG']['stigrule_103073']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103073']['Setting']['Computer_Account_Management_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103073']['Setting']['Computer_Account_Management_Ensure'] = 'Present'

# R-103075 WN19-AU-000150
default['Win2019STIG']['stigrule_103075']['Manage'] = true
default['Win2019STIG']['stigrule_103075']['Title'] = "Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout successes."
default['Win2019STIG']['stigrule_103075']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103075']['Setting']['Account_Lockout_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103075']['Setting']['Account_Lockout_Ensure'] = 'Present'

# R-103077 WN19-AU-000160
default['Win2019STIG']['stigrule_103077']['Manage'] = true
default['Win2019STIG']['stigrule_103077']['Title'] = "Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout failures."
default['Win2019STIG']['stigrule_103077']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103077']['Setting']['Account_Lockout_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103077']['Setting']['Account_Lockout_Ensure'] = 'Present'

# R-103083 WN19-DC-000340
default['Win2019STIG']['stigrule_103083']['Manage'] = false
default['Win2019STIG']['stigrule_103083']['Title'] = "Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and  Enterprise Domain Controllers groups on domain controllers."
default['Win2019STIG']['stigrule_103083']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103083']['Setting']['Access_this_computer_from_the_network_Identity'] = ['Administrators','Authenticated Users','Enterprise Domain Controllers']

# R-103095 WN19-MS-000070
default['Win2019STIG']['stigrule_103095']['Manage'] = false
default['Win2019STIG']['stigrule_103095']['Title'] = "Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone systems."
default['Win2019STIG']['stigrule_103095']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103095']['Setting']['Access_this_computer_from_the_network_Identity'] = ['Administrators','Authenticated Users']

# R-103085 WN19-DC-000360
default['Win2019STIG']['stigrule_103085']['Manage'] = true
default['Win2019STIG']['stigrule_103085']['Title'] = "Windows Server 2019 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers."
default['Win2019STIG']['stigrule_103085']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103085']['Setting']['Allow_log_on_through_Remote_Desktop_Services_Identity'] = ['Administrators']

# R-103087 WN19-DC-000370
default['Win2019STIG']['stigrule_103087']['Manage'] = false
default['Win2019STIG']['stigrule_103087']['Title'] = "Windows Server 2019 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access."
default['Win2019STIG']['stigrule_103087']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103087']['Setting']['Deny_access_to_this_computer_from_the_network_Identity'] = ['Guests']

# R-103097 WN19-MS-000080
default['Win2019STIG']['stigrule_103097']['Manage'] = false
default['Win2019STIG']['stigrule_103097']['Title'] = "Windows Server 2019 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems."
default['Win2019STIG']['stigrule_103097']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103097']['Setting']['Deny_access_to_this_computer_from_the_network_Identity'] = ['Enterprise Admins','Domain Admins','Local account','Guests']

# R-103089 WN19-DC-000380
default['Win2019STIG']['stigrule_103089']['Manage'] = false
default['Win2019STIG']['stigrule_103089']['Title'] = "Windows Server 2019 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access."
default['Win2019STIG']['stigrule_103089']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103089']['Setting']['Deny_log_on_as_a_batch_job_Identity'] = ['Guests']

# R-103099 WN19-MS-000090
default['Win2019STIG']['stigrule_103099']['Manage'] = false
default['Win2019STIG']['stigrule_103099']['Title'] = "Windows Server 2019 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
default['Win2019STIG']['stigrule_103099']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103099']['Setting']['Deny_log_on_as_a_batch_job_Identity'] = ['Enterprise Admins','Domain Admins','Guests']

# R-103091 WN19-DC-000390
default['Win2019STIG']['stigrule_103091']['Manage'] = false
default['Win2019STIG']['stigrule_103091']['Title'] = "Windows Server 2019 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers."
default['Win2019STIG']['stigrule_103091']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103091']['Setting']['Deny_log_on_as_a_service_Identity'] = ['']

# R-103101 WN19-MS-000100
default['Win2019STIG']['stigrule_103101']['Manage'] = false
default['Win2019STIG']['stigrule_103101']['Title'] = "Windows Server 2019 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right."
default['Win2019STIG']['stigrule_103101']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103101']['Setting']['Deny_log_on_as_a_service_Identity'] = ['Enterprise Admins','Domain Admins']

# R-103093 WN19-DC-000400
default['Win2019STIG']['stigrule_103093']['Manage'] = false
default['Win2019STIG']['stigrule_103093']['Title'] = "Windows Server 2019 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access."
default['Win2019STIG']['stigrule_103093']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103093']['Setting']['Deny_log_on_locally_Identity'] = ['Guests']

# R-103103 WN19-MS-000110
default['Win2019STIG']['stigrule_103103']['Manage'] = false
default['Win2019STIG']['stigrule_103103']['Title'] = "Windows Server 2019 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
default['Win2019STIG']['stigrule_103103']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103103']['Setting']['Deny_log_on_locally_Identity'] = ['Enterprise Admins','Domain Admins','Guests']

# R-103105 WN19-UR-000030
default['Win2019STIG']['stigrule_103105']['Manage'] = true
default['Win2019STIG']['stigrule_103105']['Title'] = "Windows Server 2019 Allow log on locally user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103105']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103105']['Setting']['Allow_log_on_locally_Identity'] = ['Administrators']

# R-103127 WN19-DC-000350
default['Win2019STIG']['stigrule_103127']['Manage'] = true
default['Win2019STIG']['stigrule_103127']['Title'] = "Windows Server 2019 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers."
default['Win2019STIG']['stigrule_103127']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103127']['Setting']['Add_workstations_to_domain_Identity'] = ['Administrators']

# R-103129 WN19-DC-000420
default['Win2019STIG']['stigrule_103129']['Manage'] = false
default['Win2019STIG']['stigrule_103129']['Title'] = "Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers."
default['Win2019STIG']['stigrule_103129']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103129']['Setting']['Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity'] = ['Administrators']

# R-103135 WN19-MS-000130
default['Win2019STIG']['stigrule_103135']['Manage'] = false
default['Win2019STIG']['stigrule_103135']['Title'] = "Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone systems."
default['Win2019STIG']['stigrule_103135']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103135']['Setting']['Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity'] = ['']

# R-103137 WN19-UR-000010
default['Win2019STIG']['stigrule_103137']['Manage'] = true
default['Win2019STIG']['stigrule_103137']['Title'] = "Windows Server 2019 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."
default['Win2019STIG']['stigrule_103137']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103137']['Setting']['Access_Credential_Manager_as_a_trusted_caller_Identity'] = ['']

# R-103139 WN19-UR-000020
default['Win2019STIG']['stigrule_103139']['Manage'] = true
default['Win2019STIG']['stigrule_103139']['Title'] = "Windows Server 2019 Act as part of the operating system user right must not be assigned to any groups or accounts."
default['Win2019STIG']['stigrule_103139']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103139']['Setting']['Act_as_part_of_the_operating_system_Identity'] = ['']

# R-103141 WN19-UR-000040
default['Win2019STIG']['stigrule_103141']['Manage'] = true
default['Win2019STIG']['stigrule_103141']['Title'] = "Windows Server 2019 Back up files and directories user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103141']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103141']['Setting']['Back_up_files_and_directories_Identity'] = ['Administrators']

# R-103143 WN19-UR-000050
default['Win2019STIG']['stigrule_103143']['Manage'] = true
default['Win2019STIG']['stigrule_103143']['Title'] = "Windows Server 2019 Create a pagefile user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103143']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103143']['Setting']['Create_a_pagefile_Identity'] = ['Administrators']

# R-103145 WN19-UR-000060
default['Win2019STIG']['stigrule_103145']['Manage'] = true
default['Win2019STIG']['stigrule_103145']['Title'] = "Windows Server 2019 Create a token object user right must not be assigned to any groups or accounts."
default['Win2019STIG']['stigrule_103145']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103145']['Setting']['Create_a_token_object_Identity'] = ['']

# R-103147 WN19-UR-000070
default['Win2019STIG']['stigrule_103147']['Manage'] = true
default['Win2019STIG']['stigrule_103147']['Title'] = "Windows Server 2019 Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."
default['Win2019STIG']['stigrule_103147']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103147']['Setting']['Create_global_objects_Identity'] = ['Administrators','Service','Local Service','Network Service']

# R-103149 WN19-UR-000080
default['Win2019STIG']['stigrule_103149']['Manage'] = true
default['Win2019STIG']['stigrule_103149']['Title'] = "Windows Server 2019 Create permanent shared objects user right must not be assigned to any groups or accounts."
default['Win2019STIG']['stigrule_103149']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103149']['Setting']['Create_permanent_shared_objects_Identity'] = ['']

# R-103151 WN19-UR-000090
default['Win2019STIG']['stigrule_103151']['Manage'] = true
default['Win2019STIG']['stigrule_103151']['Title'] = "Windows Server 2019 Create symbolic links user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103151']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103151']['Setting']['Create_symbolic_links_Identity'] = ['Administrators']

# R-103153 WN19-UR-000100
default['Win2019STIG']['stigrule_103153']['Manage'] = true
default['Win2019STIG']['stigrule_103153']['Title'] = "Windows Server 2019 Debug programs: user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103153']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103153']['Setting']['Debug_programs_Identity'] = ['Administrators']

# R-103155 WN19-UR-000110
default['Win2019STIG']['stigrule_103155']['Manage'] = true
default['Win2019STIG']['stigrule_103155']['Title'] = "Windows Server 2019 Force shutdown from a remote system user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103155']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103155']['Setting']['Force_shutdown_from_a_remote_system_Identity'] = ['Administrators']

# R-103157 WN19-UR-000120
default['Win2019STIG']['stigrule_103157']['Manage'] = true
default['Win2019STIG']['stigrule_103157']['Title'] = "Windows Server 2019 Generate security audits user right must only be assigned to Local Service and Network Service."
default['Win2019STIG']['stigrule_103157']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103157']['Setting']['Generate_security_audits_Identity'] = ['Local Service','Network Service']

# R-103159 WN19-UR-000130
default['Win2019STIG']['stigrule_103159']['Manage'] = true
default['Win2019STIG']['stigrule_103159']['Title'] = "Windows Server 2019 Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."
default['Win2019STIG']['stigrule_103159']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103159']['Setting']['Impersonate_a_client_after_authentication_Identity'] = ['Administrators','Service','Local Service','Network Service']

# R-103161 WN19-UR-000140
default['Win2019STIG']['stigrule_103161']['Manage'] = true
default['Win2019STIG']['stigrule_103161']['Title'] = "Windows Server 2019 Increase scheduling priority: user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103161']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103161']['Setting']['Increase_scheduling_priority_Identity'] = ['Administrators']

# R-103163 WN19-UR-000150
default['Win2019STIG']['stigrule_103163']['Manage'] = true
default['Win2019STIG']['stigrule_103163']['Title'] = "Windows Server 2019 Load and unload device drivers user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103163']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103163']['Setting']['Load_and_unload_device_drivers_Identity'] = ['Administrators']

# R-103165 WN19-UR-000160
default['Win2019STIG']['stigrule_103165']['Manage'] = true
default['Win2019STIG']['stigrule_103165']['Title'] = "Windows Server 2019 Lock pages in memory user right must not be assigned to any groups or accounts."
default['Win2019STIG']['stigrule_103165']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103165']['Setting']['Lock_pages_in_memory_Identity'] = ['']

# R-103167 WN19-UR-000180
default['Win2019STIG']['stigrule_103167']['Manage'] = true
default['Win2019STIG']['stigrule_103167']['Title'] = "Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103167']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103167']['Setting']['Modify_firmware_environment_values_Identity'] = ['Administrators']

# R-103169 WN19-UR-000190
default['Win2019STIG']['stigrule_103169']['Manage'] = true
default['Win2019STIG']['stigrule_103169']['Title'] = "Windows Server 2019 Perform volume maintenance tasks user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103169']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103169']['Setting']['Perform_volume_maintenance_tasks_Identity'] = ['Administrators']

# R-103171 WN19-UR-000200
default['Win2019STIG']['stigrule_103171']['Manage'] = true
default['Win2019STIG']['stigrule_103171']['Title'] = "Windows Server 2019 Profile single process user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103171']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103171']['Setting']['Profile_single_process_Identity'] = ['Administrators']

# R-103173 WN19-UR-000210
default['Win2019STIG']['stigrule_103173']['Manage'] = true
default['Win2019STIG']['stigrule_103173']['Title'] = "Windows Server 2019 Restore files and directories user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103173']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103173']['Setting']['Restore_files_and_directories_Identity'] = ['Administrators']

# R-103175 WN19-UR-000220
default['Win2019STIG']['stigrule_103175']['Manage'] = true
default['Win2019STIG']['stigrule_103175']['Title'] = "Windows Server 2019 Take ownership of files or other objects user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103175']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103175']['Setting']['Take_ownership_of_files_or_other_objects_Identity'] = ['Administrators']

# R-103177 WN19-AU-000090
default['Win2019STIG']['stigrule_103177']['Manage'] = true
default['Win2019STIG']['stigrule_103177']['Title'] = "Windows Server 2019 must be configured to audit Account Management - Other Account Management Events successes."
default['Win2019STIG']['stigrule_103177']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103177']['Setting']['Other_Account_Management_Events_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103177']['Setting']['Other_Account_Management_Events_Ensure'] = 'Present'

# R-103179 WN19-AU-000140
default['Win2019STIG']['stigrule_103179']['Manage'] = true
default['Win2019STIG']['stigrule_103179']['Title'] = "Windows Server 2019 must be configured to audit Detailed Tracking - Process Creation successes."
default['Win2019STIG']['stigrule_103179']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103179']['Setting']['Process_Creation_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103179']['Setting']['Process_Creation_Ensure'] = 'Present'

# R-103181 WN19-AU-000260
default['Win2019STIG']['stigrule_103181']['Manage'] = true
default['Win2019STIG']['stigrule_103181']['Title'] = "Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change successes."
default['Win2019STIG']['stigrule_103181']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103181']['Setting']['Policy_Change_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103181']['Setting']['Policy_Change_Ensure'] = 'Present'

# R-103183 WN19-AU-000270
default['Win2019STIG']['stigrule_103183']['Manage'] = true
default['Win2019STIG']['stigrule_103183']['Title'] = "Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change failures."
default['Win2019STIG']['stigrule_103183']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103183']['Setting']['Policy_Change_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103183']['Setting']['Policy_Change_Ensure'] = 'Present'

# R-103185 WN19-AU-000280
default['Win2019STIG']['stigrule_103185']['Manage'] = true
default['Win2019STIG']['stigrule_103185']['Title'] = "Windows Server 2019 must be configured to audit Policy Change - Authentication Policy Change successes."
default['Win2019STIG']['stigrule_103185']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103185']['Setting']['Authentication_Policy_Change_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103185']['Setting']['Authentication_Policy_Change_Ensure'] = 'Present'

# R-103187 WN19-AU-000290
default['Win2019STIG']['stigrule_103187']['Manage'] = true
default['Win2019STIG']['stigrule_103187']['Title'] = "Windows Server 2019 must be configured to audit Policy Change - Authorization Policy Change successes."
default['Win2019STIG']['stigrule_103187']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103187']['Setting']['Authorization_Policy_Change_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103187']['Setting']['Authorization_Policy_Change_Ensure'] = 'Present'

# R-103189 WN19-AU-000300
default['Win2019STIG']['stigrule_103189']['Manage'] = true
default['Win2019STIG']['stigrule_103189']['Title'] = "Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use successes."
default['Win2019STIG']['stigrule_103189']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103189']['Setting']['Sensitive_Privilege_Use_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103189']['Setting']['Sensitive_Privilege_Use_Ensure'] = 'Present'

# R-103191 WN19-AU-000310
default['Win2019STIG']['stigrule_103191']['Manage'] = true
default['Win2019STIG']['stigrule_103191']['Title'] = "Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures."
default['Win2019STIG']['stigrule_103191']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103191']['Setting']['Sensitive_Privilege_Use_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103191']['Setting']['Sensitive_Privilege_Use_Ensure'] = 'Present'

# R-103193 WN19-AU-000320
default['Win2019STIG']['stigrule_103193']['Manage'] = true
default['Win2019STIG']['stigrule_103193']['Title'] = "Windows Server 2019 must be configured to audit System - IPsec Driver successes."
default['Win2019STIG']['stigrule_103193']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103193']['Setting']['IPsec_Driver_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103193']['Setting']['IPsec_Driver_Ensure'] = 'Present'

# R-103195 WN19-AU-000330
default['Win2019STIG']['stigrule_103195']['Manage'] = true
default['Win2019STIG']['stigrule_103195']['Title'] = "Windows Server 2019 must be configured to audit System - IPsec Driver failures."
default['Win2019STIG']['stigrule_103195']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103195']['Setting']['IPsec_Driver_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103195']['Setting']['IPsec_Driver_Ensure'] = 'Present'

# R-103197 WN19-AU-000340
default['Win2019STIG']['stigrule_103197']['Manage'] = true
default['Win2019STIG']['stigrule_103197']['Title'] = "Windows Server 2019 must be configured to audit System - Other System Events successes."
default['Win2019STIG']['stigrule_103197']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103197']['Setting']['Other_System_Events_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103197']['Setting']['Other_System_Events_Ensure'] = 'Present'

# R-103199 WN19-AU-000350
default['Win2019STIG']['stigrule_103199']['Manage'] = true
default['Win2019STIG']['stigrule_103199']['Title'] = "Windows Server 2019 must be configured to audit System - Other System Events failures."
default['Win2019STIG']['stigrule_103199']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103199']['Setting']['Other_System_Events_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103199']['Setting']['Other_System_Events_Ensure'] = 'Present'

# R-103201 WN19-AU-000360
default['Win2019STIG']['stigrule_103201']['Manage'] = true
default['Win2019STIG']['stigrule_103201']['Title'] = "Windows Server 2019 must be configured to audit System - Security State Change successes."
default['Win2019STIG']['stigrule_103201']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103201']['Setting']['Security_State_Change_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103201']['Setting']['Security_State_Change_Ensure'] = 'Present'

# R-103203 WN19-AU-000370
default['Win2019STIG']['stigrule_103203']['Manage'] = true
default['Win2019STIG']['stigrule_103203']['Title'] = "Windows Server 2019 must be configured to audit System - Security System Extension successes."
default['Win2019STIG']['stigrule_103203']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103203']['Setting']['Security_System_Extension_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103203']['Setting']['Security_System_Extension_Ensure'] = 'Present'

# R-103205 WN19-AU-000380
default['Win2019STIG']['stigrule_103205']['Manage'] = true
default['Win2019STIG']['stigrule_103205']['Title'] = "Windows Server 2019 must be configured to audit System - System Integrity successes."
default['Win2019STIG']['stigrule_103205']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103205']['Setting']['System_Integrity_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103205']['Setting']['System_Integrity_Ensure'] = 'Present'

# R-103207 WN19-AU-000390
default['Win2019STIG']['stigrule_103207']['Manage'] = true
default['Win2019STIG']['stigrule_103207']['Title'] = "Windows Server 2019 must be configured to audit System - System Integrity failures."
default['Win2019STIG']['stigrule_103207']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103207']['Setting']['System_Integrity_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103207']['Setting']['System_Integrity_Ensure'] = 'Present'

# R-103221 WN19-DC-000240
default['Win2019STIG']['stigrule_103221']['Manage'] = true
default['Win2019STIG']['stigrule_103221']['Title'] = "Windows Server 2019 must be configured to audit DS Access - Directory Service Access successes."
default['Win2019STIG']['stigrule_103221']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103221']['Setting']['Directory_Service_Access_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103221']['Setting']['Directory_Service_Access_Ensure'] = 'Present'

# R-103223 WN19-DC-000250
default['Win2019STIG']['stigrule_103223']['Manage'] = true
default['Win2019STIG']['stigrule_103223']['Title'] = "Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures."
default['Win2019STIG']['stigrule_103223']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103223']['Setting']['Directory_Service_Access_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103223']['Setting']['Directory_Service_Access_Ensure'] = 'Present'

# R-103225 WN19-DC-000260
default['Win2019STIG']['stigrule_103225']['Manage'] = true
default['Win2019STIG']['stigrule_103225']['Title'] = "Windows Server 2019 must be configured to audit DS Access - Directory Service Changes successes."
default['Win2019STIG']['stigrule_103225']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103225']['Setting']['Directory_Service_Changes_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103225']['Setting']['Directory_Service_Changes_Ensure'] = 'Present'

# R-103227 WN19-DC-000270
default['Win2019STIG']['stigrule_103227']['Manage'] = true
default['Win2019STIG']['stigrule_103227']['Title'] = "Windows Server 2019 must be configured to audit DS Access - Directory Service Changes failures."
default['Win2019STIG']['stigrule_103227']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103227']['Setting']['Directory_Service_Changes_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103227']['Setting']['Directory_Service_Changes_Ensure'] = 'Present'

# R-103229 WN19-AC-000020
default['Win2019STIG']['stigrule_103229']['Manage'] = true
default['Win2019STIG']['stigrule_103229']['Title'] = "Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less."
default['Win2019STIG']['stigrule_103229']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103229']['Setting']['Account_lockout_threshold'] = 3

# R-103231 WN19-AC-000030
default['Win2019STIG']['stigrule_103231']['Manage'] = true
default['Win2019STIG']['stigrule_103231']['Title'] = "Windows Server 2019 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."
default['Win2019STIG']['stigrule_103231']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103231']['Setting']['Reset_account_lockout_counter_after'] = 15

# R-103233 WN19-AC-000010
default['Win2019STIG']['stigrule_103233']['Manage'] = true
default['Win2019STIG']['stigrule_103233']['Title'] = "Windows Server 2019 account lockout duration must be configured to 15 minutes or greater."
default['Win2019STIG']['stigrule_103233']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103233']['Setting']['Account_lockout_duration'] = 15

# R-103235 WN19-SO-000130
default['Win2019STIG']['stigrule_103235']['Manage'] = true
default['Win2019STIG']['stigrule_103235']['Title'] = "Windows Server 2019 required legal notice must be configured to display before console logon."
default['Win2019STIG']['stigrule_103235']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103235']['Setting']['Interactive_logon_Message_text_for_users_attempting_to_log_on'] = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'

# R-103237 WN19-SO-000140
default['Win2019STIG']['stigrule_103237']['Manage'] = true
default['Win2019STIG']['stigrule_103237']['Title'] = "Windows Server 2019 title for legal banner dialog box must be configured with the appropriate text."
default['Win2019STIG']['stigrule_103237']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103237']['Setting']['Interactive_logon_Message_title_for_users_attempting_to_log_on'] = 'DoD Notice and Consent Banner'

# R-103239 WN19-SO-000050
default['Win2019STIG']['stigrule_103239']['Manage'] = true
default['Win2019STIG']['stigrule_103239']['Title'] = "Windows Server 2019 must force audit policy subcategory settings to override audit policy category settings."
default['Win2019STIG']['stigrule_103239']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103239']['Setting']['Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'] = 'Enabled'

# R-103241 WN19-AU-000070
default['Win2019STIG']['stigrule_103241']['Manage'] = true
default['Win2019STIG']['stigrule_103241']['Title'] = "Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes."
default['Win2019STIG']['stigrule_103241']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103241']['Setting']['Credential_Validation_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103241']['Setting']['Credential_Validation_Ensure'] = 'Present'

# R-103243 WN19-AU-000080
default['Win2019STIG']['stigrule_103243']['Manage'] = true
default['Win2019STIG']['stigrule_103243']['Title'] = "Windows Server 2019 must be configured to audit Account Logon - Credential Validation failures."
default['Win2019STIG']['stigrule_103243']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103243']['Setting']['Credential_Validation_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103243']['Setting']['Credential_Validation_Ensure'] = 'Present'

# R-103245 WN19-AU-000130
default['Win2019STIG']['stigrule_103245']['Manage'] = true
default['Win2019STIG']['stigrule_103245']['Title'] = "Windows Server 2019 must be configured to audit Detailed Tracking - Plug and Play Events successes."
default['Win2019STIG']['stigrule_103245']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103245']['Setting']['PNP_Activity_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103245']['Setting']['PNP_Activity_Ensure'] = 'Present'

# R-103247 WN19-AU-000170
default['Win2019STIG']['stigrule_103247']['Manage'] = true
default['Win2019STIG']['stigrule_103247']['Title'] = "Windows Server 2019 must be configured to audit Logon/Logoff - Group Membership successes."
default['Win2019STIG']['stigrule_103247']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103247']['Setting']['Group_Membership_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103247']['Setting']['Group_Membership_Ensure'] = 'Present'

# R-103249 WN19-AU-000210
default['Win2019STIG']['stigrule_103249']['Manage'] = true
default['Win2019STIG']['stigrule_103249']['Title'] = "Windows Server 2019 must be configured to audit Logon/Logoff - Special Logon successes."
default['Win2019STIG']['stigrule_103249']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103249']['Setting']['Special_Logon_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103249']['Setting']['Special_Logon_Ensure'] = 'Present'

# R-103251 WN19-AU-000220
default['Win2019STIG']['stigrule_103251']['Manage'] = true
default['Win2019STIG']['stigrule_103251']['Title'] = "Windows Server 2019 must be configured to audit Object Access - Other Object Access Events successes."
default['Win2019STIG']['stigrule_103251']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103251']['Setting']['Other_Object_Access_Events_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103251']['Setting']['Other_Object_Access_Events_Ensure'] = 'Present'

# R-103253 WN19-AU-000230
default['Win2019STIG']['stigrule_103253']['Manage'] = true
default['Win2019STIG']['stigrule_103253']['Title'] = "Windows Server 2019 must be configured to audit Object Access - Other Object Access Events failures."
default['Win2019STIG']['stigrule_103253']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103253']['Setting']['Other_Object_Access_Events_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103253']['Setting']['Other_Object_Access_Events_Ensure'] = 'Present'

# R-103255 WN19-AU-000240
default['Win2019STIG']['stigrule_103255']['Manage'] = true
default['Win2019STIG']['stigrule_103255']['Title'] = "Windows Server 2019 must be configured to audit Object Access - Removable Storage successes."
default['Win2019STIG']['stigrule_103255']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103255']['Setting']['Removable_Storage_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103255']['Setting']['Removable_Storage_Ensure'] = 'Present'

# R-103257 WN19-AU-000250
default['Win2019STIG']['stigrule_103257']['Manage'] = true
default['Win2019STIG']['stigrule_103257']['Title'] = "Windows Server 2019 must be configured to audit Object Access - Removable Storage failures."
default['Win2019STIG']['stigrule_103257']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103257']['Setting']['Removable_Storage_AuditFlag'] = 'Failure'
default['Win2019STIG']['stigrule_103257']['Setting']['Removable_Storage_Ensure'] = 'Present'

# R-103259 WN19-AU-000180
default['Win2019STIG']['stigrule_103259']['Manage'] = true
default['Win2019STIG']['stigrule_103259']['Title'] = "Windows Server 2019 must be configured to audit logoff successes."
default['Win2019STIG']['stigrule_103259']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103259']['Setting']['Logoff_AuditFlag'] = 'Success'
default['Win2019STIG']['stigrule_103259']['Setting']['Logoff_Ensure'] = 'Present'

# R-103261 WN19-CC-000090
default['Win2019STIG']['stigrule_103261']['Manage'] = true
default['Win2019STIG']['stigrule_103261']['Title'] = "Windows Server 2019 command line data must be included in process creation events."
default['Win2019STIG']['stigrule_103261']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
default['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_ValueType'] = :dword
default['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_ValueData'] = '1'
default['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_Ensure'] = :create

# R-103263 WN19-CC-000460
default['Win2019STIG']['stigrule_103263']['Manage'] = true
default['Win2019STIG']['stigrule_103263']['Title'] = "Windows Server 2019 PowerShell script block logging must be enabled."
default['Win2019STIG']['stigrule_103263']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
default['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_ValueType'] = :dword
default['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_ValueData'] = '1'
default['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_Ensure'] = :create

# R-103265 WN19-CC-000270
default['Win2019STIG']['stigrule_103265']['Manage'] = true
default['Win2019STIG']['stigrule_103265']['Title'] = "Windows Server 2019 Application event log size must be configured to 32768 KB or greater."
default['Win2019STIG']['stigrule_103265']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
default['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_ValueType'] = :dword
default['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_ValueData'] = '32768'
default['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_Ensure'] = :create

# R-103267 WN19-CC-000280
default['Win2019STIG']['stigrule_103267']['Manage'] = true
default['Win2019STIG']['stigrule_103267']['Title'] = "Windows Server 2019 Security event log size must be configured to 196608 KB or greater."
default['Win2019STIG']['stigrule_103267']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
default['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_ValueType'] = :dword
default['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_ValueData'] = '196608'
default['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_Ensure'] = :create

# R-103269 WN19-CC-000290
default['Win2019STIG']['stigrule_103269']['Manage'] = true
default['Win2019STIG']['stigrule_103269']['Title'] = "Windows Server 2019 System event log size must be configured to 32768 KB or greater."
default['Win2019STIG']['stigrule_103269']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
default['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_ValueType'] = :dword
default['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_ValueData'] = '32768'
default['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_Ensure'] = :create

# R-103275 WN19-00-000440
# Please choose an appropriate DoD time source from http://tycho.usno.navy.mil/ntp.html
default['Win2019STIG']['stigrule_103275']['Manage'] = false
default['Win2019STIG']['stigrule_103275']['Title'] = "The Windows Server 2019 time service must synchronize with an appropriate DoD time source."
default['Win2019STIG']['stigrule_103275']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters'
default['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_ValueType'] = :string
default['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_ValueData'] = 'your|DoD|time|server|url|here'
default['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['Type_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\Parameters'
default['Win2019STIG']['stigrule_103275']['Setting']['Type_ValueType'] = :string
default['Win2019STIG']['stigrule_103275']['Setting']['Type_ValueData'] = 'NTP'
default['Win2019STIG']['stigrule_103275']['Setting']['Type_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
default['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_ValueType'] = :dword
default['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_ValueData'] = '2'
default['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
default['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_ValueType'] = :dword
default['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_ValueData'] = '0'
default['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_ValueType'] = :dword
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_ValueData'] = '7'
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_ValueType'] = :dword
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_ValueData'] = '15'
default['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_Ensure'] = :create

default['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient'
default['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_ValueType'] = :dword
default['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_ValueData'] = '3600'
default['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_Ensure'] = :create

# R-103277 WN19-AU-000030
default['Win2019STIG']['stigrule_103277']['Manage'] = true
default['Win2019STIG']['stigrule_103277']['Title'] = "Windows Server 2019 permissions for the Application event log must prevent access by non-privileged accounts."
default['Win2019STIG']['stigrule_103277']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Path'] = 'C:\Windows\System32\winevt\Logs\Application.evtx'
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Inherits'] = false
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_1'] = :full_control
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_1'] = 'NT SERVICE\EventLog'
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_2'] = :full_control
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_2'] = 'SYSTEM'
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_3'] = :full_control
default['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_3'] = 'Administrators'

# R-103279 WN19-AU-000040
default['Win2019STIG']['stigrule_103279']['Manage'] = true
default['Win2019STIG']['stigrule_103279']['Title'] = "Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts."
default['Win2019STIG']['stigrule_103279']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Path'] = 'C:\Windows\System32\winevt\Logs\Security.evtx'
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Inherits'] = false
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_1'] = :full_control
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_1'] = 'NT SERVICE\EventLog'
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_2'] = :full_control
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_2'] = 'SYSTEM'
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_3'] = :full_control
default['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_3'] = 'Administrators'

# R-103281 WN19-AU-000050
default['Win2019STIG']['stigrule_103281']['Manage'] = true
default['Win2019STIG']['stigrule_103281']['Title'] = "Windows Server 2019 permissions for the System event log must prevent access by non-privileged accounts."
default['Win2019STIG']['stigrule_103281']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Path'] = 'C:\Windows\System32\winevt\Logs\System.evtx'
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Inherits'] = false
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_1'] = :full_control
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_1'] = 'NT SERVICE\EventLog'
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_2'] = :full_control
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_2'] = 'SYSTEM'
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_3'] = :full_control
default['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_3'] = 'Administrators'

# R-103285 WN19-UR-000170
default['Win2019STIG']['stigrule_103285']['Manage'] = true
default['Win2019STIG']['stigrule_103285']['Title'] = "Windows Server 2019 Manage auditing and security log user right must only be assigned to the Administrators group."
default['Win2019STIG']['stigrule_103285']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103285']['Setting']['Manage_auditing_and_security_log_Identity'] = ['Administrators']

# R-103287 WN19-CC-000420
default['Win2019STIG']['stigrule_103287']['Manage'] = true
default['Win2019STIG']['stigrule_103287']['Title'] = "Windows Server 2019 must prevent users from changing installation options."
default['Win2019STIG']['stigrule_103287']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
default['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_ValueType'] = :dword
default['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_ValueData'] = '0'
default['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_Ensure'] = :create

# R-103289 WN19-CC-000430
default['Win2019STIG']['stigrule_103289']['Manage'] = true
default['Win2019STIG']['stigrule_103289']['Title'] = "Windows Server 2019 must disable the Windows Installer Always install with elevated privileges option."
default['Win2019STIG']['stigrule_103289']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
default['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_ValueType'] = :dword
default['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_ValueData'] = '0'
default['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_Ensure'] = :create

# R-103321 WN19-CC-000030
default['Win2019STIG']['stigrule_103321']['Manage'] = true
default['Win2019STIG']['stigrule_103321']['Title'] = "Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."
default['Win2019STIG']['stigrule_103321']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
default['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_ValueType'] = :dword
default['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_ValueData'] = '2'
default['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_Ensure'] = :create

# R-103323 WN19-CC-000040
default['Win2019STIG']['stigrule_103323']['Manage'] = true
default['Win2019STIG']['stigrule_103323']['Title'] = "Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."
default['Win2019STIG']['stigrule_103323']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
default['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_ValueType'] = :dword
default['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_ValueData'] = '2'
default['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_Ensure'] = :create

# R-103325 WN19-CC-000050
default['Win2019STIG']['stigrule_103325']['Manage'] = true
default['Win2019STIG']['stigrule_103325']['Title'] = "Windows Server 2019 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."
default['Win2019STIG']['stigrule_103325']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
default['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_ValueType'] = :dword
default['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_ValueData'] = '0'
default['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_Ensure'] = :create

# R-103327 WN19-CC-000070
default['Win2019STIG']['stigrule_103327']['Manage'] = true
default['Win2019STIG']['stigrule_103327']['Title'] = "Windows Server 2019 insecure logons to an SMB server must be disabled."
default['Win2019STIG']['stigrule_103327']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
default['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_ValueType'] = :dword
default['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_ValueData'] = '0'
default['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_Ensure'] = :create

# R-103329 WN19-CC-000080
default['Win2019STIG']['stigrule_103329']['Manage'] = true
default['Win2019STIG']['stigrule_103329']['Title'] = "Windows Server 2019 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."
default['Win2019STIG']['stigrule_103329']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
default['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_ValueType'] = :string
default['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_ValueData'] = 'RequireMutualAuthentication=1, RequireIntegrity=1'
default['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_Ensure'] = :create

default['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
default['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_ValueType'] = :string
default['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_ValueData'] = 'RequireMutualAuthentication=1, RequireIntegrity=1'
default['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_Ensure'] = :create

# R-103331 WN19-CC-000100
default['Win2019STIG']['stigrule_103331']['Manage'] = true
default['Win2019STIG']['stigrule_103331']['Title'] = "Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials."
default['Win2019STIG']['stigrule_103331']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
default['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_ValueType'] = :dword
default['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_ValueData'] = '1'
default['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_Ensure'] = :create

# R-103333 WN19-CC-000110
# Please ensure the hardware requirements are met. See https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements
default['Win2019STIG']['stigrule_103333']['Manage'] = false
default['Win2019STIG']['stigrule_103333']['Title'] = "Windows Server 2019 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."
default['Win2019STIG']['stigrule_103333']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
default['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_ValueType'] = :dword
default['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_ValueData'] = '1'
default['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_Ensure'] = :create

default['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
default['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_ValueType'] = :dword
default['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_ValueData'] = '1'
default['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_Ensure'] = :create

# R-103337 WN19-CC-000130
default['Win2019STIG']['stigrule_103337']['Manage'] = true
default['Win2019STIG']['stigrule_103337']['Title'] = "Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad."
default['Win2019STIG']['stigrule_103337']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
default['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_ValueType'] = :dword
default['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_ValueData'] = '1'
default['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_Ensure'] = :create

# R-103339 WN19-CC-000140
default['Win2019STIG']['stigrule_103339']['Manage'] = true
default['Win2019STIG']['stigrule_103339']['Title'] = "Windows Server 2019 group policy objects must be reprocessed even if they have not changed."
default['Win2019STIG']['stigrule_103339']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
default['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_ValueType'] = :dword
default['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_ValueData'] = '0'
default['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_Ensure'] = :create

# R-103341 WN19-CC-000180
default['Win2019STIG']['stigrule_103341']['Manage'] = true
default['Win2019STIG']['stigrule_103341']['Title'] = "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery)."
default['Win2019STIG']['stigrule_103341']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
default['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_ValueType'] = :dword
default['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_ValueData'] = '1'
default['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_Ensure'] = :create

# R-103343 WN19-CC-000190
default['Win2019STIG']['stigrule_103343']['Manage'] = true
default['Win2019STIG']['stigrule_103343']['Title'] = "Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (plugged in)."
default['Win2019STIG']['stigrule_103343']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
default['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_ValueType'] = :dword
default['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_ValueData'] = '1'
default['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_Ensure'] = :create

# R-103345 WN19-CC-000250
default['Win2019STIG']['stigrule_103345']['Manage'] = true
default['Win2019STIG']['stigrule_103345']['Title'] = "Windows Server 2019 Telemetry must be configured to Security or Basic."
default['Win2019STIG']['stigrule_103345']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
default['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_ValueType'] = :dword
default['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_ValueData'] = '1'
default['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_Ensure'] = :create

# R-103347 WN19-CC-000260
default['Win2019STIG']['stigrule_103347']['Manage'] = true
default['Win2019STIG']['stigrule_103347']['Title'] = "Windows Server 2019 Windows Update must not obtain updates from other PCs on the Internet."
default['Win2019STIG']['stigrule_103347']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
default['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_ValueType'] = :dword
default['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_ValueData'] = '100'
default['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_Ensure'] = :create

# R-103349 WN19-CC-000320
default['Win2019STIG']['stigrule_103349']['Manage'] = true
default['Win2019STIG']['stigrule_103349']['Title'] = "Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled."
default['Win2019STIG']['stigrule_103349']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
default['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_ValueType'] = :dword
default['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_ValueData'] = '0'
default['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_Ensure'] = :create

# R-103351 WN19-CC-000330
default['Win2019STIG']['stigrule_103351']['Manage'] = true
default['Win2019STIG']['stigrule_103351']['Title'] = "Windows Server 2019 File Explorer shell protocol must run in protected mode."
default['Win2019STIG']['stigrule_103351']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
default['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_ValueType'] = :dword
default['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_ValueData'] = '0'
default['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_Ensure'] = :create

# R-103353 WN19-CC-000390
default['Win2019STIG']['stigrule_103353']['Manage'] = true
default['Win2019STIG']['stigrule_103353']['Title'] = "Windows Server 2019 must prevent attachments from being downloaded from RSS feeds."
default['Win2019STIG']['stigrule_103353']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
default['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_ValueType'] = :dword
default['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_ValueData'] = '1'
default['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_Ensure'] = :create

# R-103355 WN19-CC-000440
default['Win2019STIG']['stigrule_103355']['Manage'] = true
default['Win2019STIG']['stigrule_103355']['Title'] = "Windows Server 2019 users must be notified if a web-based program attempts to install software."
default['Win2019STIG']['stigrule_103355']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
default['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_ValueType'] = :dword
default['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_ValueData'] = '0'
default['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_Ensure'] = :create

# R-103357 WN19-CC-000450
default['Win2019STIG']['stigrule_103357']['Manage'] = true
default['Win2019STIG']['stigrule_103357']['Title'] = "Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart."
default['Win2019STIG']['stigrule_103357']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
default['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_ValueType'] = :dword
default['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_ValueData'] = '1'
default['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_Ensure'] = :create

# R-103361 WN19-DC-000330
default['Win2019STIG']['stigrule_103361']['Manage'] = true
default['Win2019STIG']['stigrule_103361']['Title'] = "Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords."
default['Win2019STIG']['stigrule_103361']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103361']['Setting']['Domain_controller_Refuse_machine_account_password_changes'] = 'Disabled'

# R-103363 WN19-MS-000050
default['Win2019STIG']['stigrule_103363']['Manage'] = true
default['Win2019STIG']['stigrule_103363']['Title'] = "Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers."
default['Win2019STIG']['stigrule_103363']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103363']['Setting']['Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'] = '4'

# R-103365 WN19-MS-000140
# Please ensure the hardware requirements are met. See https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements
default['Win2019STIG']['stigrule_103365']['Manage'] = false
default['Win2019STIG']['stigrule_103365']['Title'] = "Windows Server 2019 must be running Credential Guard on domain-joined member servers."
default['Win2019STIG']['stigrule_103365']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
default['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_ValueType'] = :dword
default['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_ValueData'] = '1'
default['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_Ensure'] = :create

# R-103367 WN19-SO-000020
default['Win2019STIG']['stigrule_103367']['Manage'] = true
default['Win2019STIG']['stigrule_103367']['Title'] = "Windows Server 2019 must prevent local accounts with blank passwords from being used from the network."
default['Win2019STIG']['stigrule_103367']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103367']['Setting']['Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'] = 'Enabled'

# R-103369 WN19-SO-000030
default['Win2019STIG']['stigrule_103369']['Manage'] = false
default['Win2019STIG']['stigrule_103369']['Title'] = "Windows Server 2019 built-in administrator account must be renamed."
default['Win2019STIG']['stigrule_103369']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103369']['Setting']['Accounts_Rename_administrator_account'] = 'RenamedAdministrator'

# R-103371 WN19-SO-000040
default['Win2019STIG']['stigrule_103371']['Manage'] = false
default['Win2019STIG']['stigrule_103371']['Title'] = "Windows Server 2019 built-in guest account must be renamed."
default['Win2019STIG']['stigrule_103371']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103371']['Setting']['Accounts_Rename_guest_account'] = 'RenamedGuest'

# R-103373 WN19-SO-000100
default['Win2019STIG']['stigrule_103373']['Manage'] = true
default['Win2019STIG']['stigrule_103373']['Title'] = "Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less."
default['Win2019STIG']['stigrule_103373']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103373']['Setting']['Domain_member_Maximum_machine_account_password_age'] = '30'

# R-103375 WN19-SO-000150
default['Win2019STIG']['stigrule_103375']['Manage'] = true
default['Win2019STIG']['stigrule_103375']['Title'] = "Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation."
default['Win2019STIG']['stigrule_103375']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103375']['Setting']['Interactive_logon_Smart_card_removal_behavior'] = 'Lock Workstation'

# R-103377 WN19-SO-000210
default['Win2019STIG']['stigrule_103377']['Manage'] = true
default['Win2019STIG']['stigrule_103377']['Title'] = "Windows Server 2019 must not allow anonymous SID/Name translation."
default['Win2019STIG']['stigrule_103377']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103377']['Setting']['Network_access_Allow_anonymous_SID_Name_translation'] = 'Disabled'

# R-103379 WN19-SO-000220
default['Win2019STIG']['stigrule_103379']['Manage'] = true
default['Win2019STIG']['stigrule_103379']['Title'] = "Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts."
default['Win2019STIG']['stigrule_103379']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103379']['Setting']['Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'] = 'Enabled'

# R-103381 WN19-SO-000240
default['Win2019STIG']['stigrule_103381']['Manage'] = true
default['Win2019STIG']['stigrule_103381']['Title'] = "Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group."
default['Win2019STIG']['stigrule_103381']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103381']['Setting']['Network_access_Let_Everyone_permissions_apply_to_anonymous_users'] = 'Disabled'

# R-103383 WN19-SO-000260
default['Win2019STIG']['stigrule_103383']['Manage'] = true
default['Win2019STIG']['stigrule_103383']['Title'] = "Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."
default['Win2019STIG']['stigrule_103383']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103383']['Setting']['Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'] = 'Enabled'

# R-103385 WN19-SO-000270
default['Win2019STIG']['stigrule_103385']['Manage'] = true
default['Win2019STIG']['stigrule_103385']['Title'] = "Windows Server 2019 must prevent NTLM from falling back to a Null session."
default['Win2019STIG']['stigrule_103385']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103385']['Setting']['Network_security_Allow_LocalSystem_NULL_session_fallback'] = 'Disabled'

# R-103387 WN19-SO-000280
default['Win2019STIG']['stigrule_103387']['Manage'] = true
default['Win2019STIG']['stigrule_103387']['Title'] = "Windows Server 2019 must prevent PKU2U authentication using online identities."
default['Win2019STIG']['stigrule_103387']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103387']['Setting']['Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'] = 'Disabled'

# R-103389 WN19-SO-000310
default['Win2019STIG']['stigrule_103389']['Manage'] = true
default['Win2019STIG']['stigrule_103389']['Title'] = "Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."
default['Win2019STIG']['stigrule_103389']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103389']['Setting']['Network_security_LAN_Manager_authentication_level'] = 'Send NTLMv2 responses only. Refuse LM & NTLM'

# R-103391 WN19-SO-000320
default['Win2019STIG']['stigrule_103391']['Manage'] = true
default['Win2019STIG']['stigrule_103391']['Title'] = "Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing."
default['Win2019STIG']['stigrule_103391']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103391']['Setting']['Network_security_LDAP_client_signing_requirements'] = 'Negotiate signing'

# R-103393 WN19-SO-000330
default['Win2019STIG']['stigrule_103393']['Manage'] = true
default['Win2019STIG']['stigrule_103393']['Title'] = "Windows Server 2019 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."
default['Win2019STIG']['stigrule_103393']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103393']['Setting']['Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'] = 'Both options checked'

# R-103395 WN19-SO-000340
default['Win2019STIG']['stigrule_103395']['Manage'] = true
default['Win2019STIG']['stigrule_103395']['Title'] = "Windows Server 2019 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."
default['Win2019STIG']['stigrule_103395']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103395']['Setting']['Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'] = 'Both options checked'

# R-103397 WN19-SO-000370
default['Win2019STIG']['stigrule_103397']['Manage'] = true
default['Win2019STIG']['stigrule_103397']['Title'] = "Windows Server 2019 default permissions of global system objects must be strengthened."
default['Win2019STIG']['stigrule_103397']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103397']['Setting']['System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'] = 'Enabled'

# R-103399 WN19-UC-000010
default['Win2019STIG']['stigrule_103399']['Manage'] = true
default['Win2019STIG']['stigrule_103399']['Title'] = "Windows Server 2019 must preserve zone information when saving attachments."
default['Win2019STIG']['stigrule_103399']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
default['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_ValueType'] = :dword
default['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_ValueData'] = '2'
default['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_Ensure'] = :create

# R-103459 WN19-CC-000210
default['Win2019STIG']['stigrule_103459']['Manage'] = true
default['Win2019STIG']['stigrule_103459']['Title'] = "Windows Server 2019 Autoplay must be turned off for non-volume devices."
default['Win2019STIG']['stigrule_103459']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
default['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_ValueType'] = :dword
default['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_ValueData'] = '1'
default['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_Ensure'] = :create

# R-103461 WN19-CC-000220
default['Win2019STIG']['stigrule_103461']['Manage'] = true
default['Win2019STIG']['stigrule_103461']['Title'] = "Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands."
default['Win2019STIG']['stigrule_103461']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
default['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_ValueType'] = :dword
default['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_ValueData'] = '1'
default['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_Ensure'] = :create

# R-103463 WN19-CC-000230
default['Win2019STIG']['stigrule_103463']['Manage'] = true
default['Win2019STIG']['stigrule_103463']['Title'] = "Windows Server 2019 AutoPlay must be disabled for all drives."
default['Win2019STIG']['stigrule_103463']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
default['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_ValueType'] = :dword
default['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_ValueData'] = '255'
default['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_Ensure'] = :create

# R-103469 WN19-00-000320
default['Win2019STIG']['stigrule_103469']['Manage'] = true
default['Win2019STIG']['stigrule_103469']['Title'] = "Windows Server 2019 must not have the Fax Server role installed."
default['Win2019STIG']['stigrule_103469']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103469']['Setting']['Fax_Ensure'] = :remove

# R-103471 WN19-00-000340
default['Win2019STIG']['stigrule_103471']['Manage'] = true
default['Win2019STIG']['stigrule_103471']['Title'] = "Windows Server 2019 must not have the Peer Name Resolution Protocol installed."
default['Win2019STIG']['stigrule_103471']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103471']['Setting']['PNRP_Ensure'] = :remove

# R-103473 WN19-00-000350
default['Win2019STIG']['stigrule_103473']['Manage'] = true
default['Win2019STIG']['stigrule_103473']['Title'] = "Windows Server 2019 must not have Simple TCP/IP Services installed."
default['Win2019STIG']['stigrule_103473']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103473']['Setting']['Simple_TCPIP_Ensure'] = :remove

# R-103475 WN19-00-000370
default['Win2019STIG']['stigrule_103475']['Manage'] = true
default['Win2019STIG']['stigrule_103475']['Title'] = "Windows Server 2019 must not have the TFTP Client installed."
default['Win2019STIG']['stigrule_103475']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103475']['Setting']['TFTP_Client_Ensure'] = :remove

# R-103477 WN19-00-000380
default['Win2019STIG']['stigrule_103477']['Manage'] = true
default['Win2019STIG']['stigrule_103477']['Title'] = "Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed."
default['Win2019STIG']['stigrule_103477']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103477']['Setting']['FS_SMB1_Ensure'] = :remove

# R-103479 WN19-00-000390
default['Win2019STIG']['stigrule_103479']['Manage'] = true
default['Win2019STIG']['stigrule_103479']['Title'] = "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server."
default['Win2019STIG']['stigrule_103479']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103479']['Setting']['SMB1_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
default['Win2019STIG']['stigrule_103479']['Setting']['SMB1_ValueType'] = :dword
default['Win2019STIG']['stigrule_103479']['Setting']['SMB1_ValueData'] = '0'
default['Win2019STIG']['stigrule_103479']['Setting']['SMB1_Ensure'] = :create

# R-103481 WN19-00-000400
default['Win2019STIG']['stigrule_103481']['Manage'] = true
default['Win2019STIG']['stigrule_103481']['Title'] = "Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client."
default['Win2019STIG']['stigrule_103481']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103481']['Setting']['Start_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
default['Win2019STIG']['stigrule_103481']['Setting']['Start_ValueType'] = :dword
default['Win2019STIG']['stigrule_103481']['Setting']['Start_ValueData'] = '4'
default['Win2019STIG']['stigrule_103481']['Setting']['Start_Ensure'] = :create

# R-103483 WN19-00-000410
default['Win2019STIG']['stigrule_103483']['Manage'] = true
default['Win2019STIG']['stigrule_103483']['Title'] = "Windows Server 2019 must not have Windows PowerShell 2.0 installed."
default['Win2019STIG']['stigrule_103483']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103483']['Setting']['PowerShell_v2_Ensure'] = :remove

# R-103485 WN19-CC-000010
default['Win2019STIG']['stigrule_103485']['Manage'] = true
default['Win2019STIG']['stigrule_103485']['Title'] = "Windows Server 2019 must prevent the display of slide shows on the lock screen."
default['Win2019STIG']['stigrule_103485']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
default['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_ValueType'] = :dword
default['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_ValueData'] = '1'
default['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_Ensure'] = :create

# R-103487 WN19-CC-000020
default['Win2019STIG']['stigrule_103487']['Manage'] = true
default['Win2019STIG']['stigrule_103487']['Title'] = "Windows Server 2019 must have WDigest Authentication disabled."
default['Win2019STIG']['stigrule_103487']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
default['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_ValueType'] = :dword
default['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_ValueData'] = '0'
default['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_Ensure'] = :create

# R-103489 WN19-CC-000150
default['Win2019STIG']['stigrule_103489']['Manage'] = true
default['Win2019STIG']['stigrule_103489']['Title'] = "Windows Server 2019 downloading print driver packages over HTTP must be turned off."
default['Win2019STIG']['stigrule_103489']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
default['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_ValueType'] = :dword
default['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_ValueData'] = '1'
default['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_Ensure'] = :create

# R-103491 WN19-CC-000160
default['Win2019STIG']['stigrule_103491']['Manage'] = true
default['Win2019STIG']['stigrule_103491']['Title'] = "Windows Server 2019 printing over HTTP must be turned off."
default['Win2019STIG']['stigrule_103491']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
default['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_ValueType'] = :dword
default['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_ValueData'] = '1'
default['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_Ensure'] = :create

# R-103493 WN19-CC-000170
default['Win2019STIG']['stigrule_103493']['Manage'] = true
default['Win2019STIG']['stigrule_103493']['Title'] = "Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen."
default['Win2019STIG']['stigrule_103493']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
default['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_ValueType'] = :dword
default['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_ValueData'] = '1'
default['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_Ensure'] = :create

# R-103495 WN19-CC-000200
default['Win2019STIG']['stigrule_103495']['Manage'] = true
default['Win2019STIG']['stigrule_103495']['Title'] = "Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
default['Win2019STIG']['stigrule_103495']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
default['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_ValueType'] = :dword
default['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_ValueData'] = '1'
default['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_Ensure'] = :create

# R-103497 WN19-CC-000300
default['Win2019STIG']['stigrule_103497']['Manage'] = true
default['Win2019STIG']['stigrule_103497']['Title'] = "Windows Server 2019 Windows Defender SmartScreen must be enabled."
default['Win2019STIG']['stigrule_103497']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
default['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_ValueType'] = :dword
default['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_ValueData'] = '1'
default['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_Ensure'] = :create

# R-103499 WN19-CC-000400
default['Win2019STIG']['stigrule_103499']['Manage'] = true
default['Win2019STIG']['stigrule_103499']['Title'] = "Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP."
default['Win2019STIG']['stigrule_103499']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
default['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_ValueType'] = :dword
default['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_ValueData'] = '0'
default['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_Ensure'] = :create

# R-103501 WN19-CC-000410
default['Win2019STIG']['stigrule_103501']['Manage'] = true
default['Win2019STIG']['stigrule_103501']['Title'] = "Windows Server 2019 must prevent Indexing of encrypted files."
default['Win2019STIG']['stigrule_103501']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
default['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_ValueType'] = :dword
default['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_ValueData'] = '0'
default['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_Ensure'] = :create

# R-103505 WN19-MS-000030
default['Win2019STIG']['stigrule_103505']['Manage'] = true
default['Win2019STIG']['stigrule_103505']['Title'] = "Windows Server 2019 local users on domain-joined member servers must not be enumerated."
default['Win2019STIG']['stigrule_103505']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
default['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_ValueType'] = :dword
default['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_ValueData'] = '0'
default['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_Ensure'] = :create

# R-103507 WN19-00-000330
default['Win2019STIG']['stigrule_103507']['Manage'] = true
default['Win2019STIG']['stigrule_103507']['Title'] = "Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization."
default['Win2019STIG']['stigrule_103507']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103507']['Setting']['Web_Ftp_Service_Ensure'] = :remove

# R-103509 WN19-00-000360
default['Win2019STIG']['stigrule_103509']['Manage'] = true
default['Win2019STIG']['stigrule_103509']['Title'] = "Windows Server 2019 must not have the Telnet Client installed."
default['Win2019STIG']['stigrule_103509']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103509']['Setting']['Telnet_Client_Ensure'] = :remove

# R-103511 WN19-CC-000340
default['Win2019STIG']['stigrule_103511']['Manage'] = true
default['Win2019STIG']['stigrule_103511']['Title'] = "Windows Server 2019 must not save passwords in the Remote Desktop Client."
default['Win2019STIG']['stigrule_103511']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
default['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_ValueType'] = :dword
default['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_ValueData'] = '1'
default['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_Ensure'] = :create

# R-103513 WN19-CC-000360
default['Win2019STIG']['stigrule_103513']['Manage'] = true
default['Win2019STIG']['stigrule_103513']['Title'] = "Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection."
default['Win2019STIG']['stigrule_103513']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
default['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_ValueType'] = :dword
default['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_ValueData'] = '1'
default['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_Ensure'] = :create

# R-103515 WN19-CC-000520
default['Win2019STIG']['stigrule_103515']['Manage'] = true
default['Win2019STIG']['stigrule_103515']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials."
default['Win2019STIG']['stigrule_103515']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
default['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_ValueType'] = :dword
default['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_ValueData'] = '1'
default['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_Ensure'] = :create

# R-103517 WN19-SO-000380
default['Win2019STIG']['stigrule_103517']['Manage'] = true
default['Win2019STIG']['stigrule_103517']['Title'] = "Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled."
default['Win2019STIG']['stigrule_103517']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103517']['Setting']['User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'] = 'Enabled'

# R-103519 WN19-SO-000410
default['Win2019STIG']['stigrule_103519']['Manage'] = true
default['Win2019STIG']['stigrule_103519']['Title'] = "Windows Server 2019 User Account Control must automatically deny standard user requests for elevation."
default['Win2019STIG']['stigrule_103519']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103519']['Setting']['User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'] = 'Automatically deny elevation request'

# R-103521 WN19-SO-000440
default['Win2019STIG']['stigrule_103521']['Manage'] = true
default['Win2019STIG']['stigrule_103521']['Title'] = "Windows Server 2019 User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
default['Win2019STIG']['stigrule_103521']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103521']['Setting']['User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'] = 'Enabled'

# R-103539 WN19-MS-000040
default['Win2019STIG']['stigrule_103539']['Manage'] = true
default['Win2019STIG']['stigrule_103539']['Title'] = "Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems."
default['Win2019STIG']['stigrule_103539']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
default['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_ValueType'] = :dword
default['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_ValueData'] = '1'
default['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_Ensure'] = :create

# R-103541 WN19-SO-000090
default['Win2019STIG']['stigrule_103541']['Manage'] = true
default['Win2019STIG']['stigrule_103541']['Title'] = "Windows Server 2019 computer account password must not be prevented from being reset."
default['Win2019STIG']['stigrule_103541']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103541']['Setting']['Domain_member_Disable_machine_account_password_changes'] = 'Disabled'

# R-103545 WN19-AC-000080
default['Win2019STIG']['stigrule_103545']['Manage'] = true
default['Win2019STIG']['stigrule_103545']['Title'] = "Windows Server 2019 must have the built-in Windows password complexity policy enabled."
default['Win2019STIG']['stigrule_103545']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103545']['Setting']['Password_must_meet_complexity_requirements'] = 'Enabled'

# R-103549 WN19-AC-000070
default['Win2019STIG']['stigrule_103549']['Manage'] = true
default['Win2019STIG']['stigrule_103549']['Title'] = "Windows Server 2019 minimum password length must be configured to 14 characters."
default['Win2019STIG']['stigrule_103549']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103549']['Setting']['Minimum_Password_Length'] = 14

# R-103551 WN19-AC-000090
default['Win2019STIG']['stigrule_103551']['Manage'] = true
default['Win2019STIG']['stigrule_103551']['Title'] = "Windows Server 2019 reversible password encryption must be disabled."
default['Win2019STIG']['stigrule_103551']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103551']['Setting']['Store_passwords_using_reversible_encryption'] = 'Disabled'

# R-103553 WN19-SO-000300
default['Win2019STIG']['stigrule_103553']['Manage'] = true
default['Win2019STIG']['stigrule_103553']['Title'] = "Windows Server 2019 must be configured to prevent the storage of the LAN Manager hash of passwords."
default['Win2019STIG']['stigrule_103553']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103553']['Setting']['Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'] = 'Enabled'

# R-103555 WN19-SO-000180
default['Win2019STIG']['stigrule_103555']['Manage'] = true
default['Win2019STIG']['stigrule_103555']['Title'] = "Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers."
default['Win2019STIG']['stigrule_103555']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103555']['Setting']['Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'] = 'Disabled'

# R-103557 WN19-AC-000060
default['Win2019STIG']['stigrule_103557']['Manage'] = true
default['Win2019STIG']['stigrule_103557']['Title'] = "Windows Server 2019 minimum password age must be configured to at least one day."
default['Win2019STIG']['stigrule_103557']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103557']['Setting']['Minimum_Password_Age'] = 1

# R-103563 WN19-AC-000050
default['Win2019STIG']['stigrule_103563']['Manage'] = true
default['Win2019STIG']['stigrule_103563']['Title'] = "Windows Server 2019 maximum password age must be configured to 60 days or less."
default['Win2019STIG']['stigrule_103563']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103563']['Setting']['Maximum_Password_Age'] = 60

# R-103565 WN19-AC-000040
default['Win2019STIG']['stigrule_103565']['Manage'] = true
default['Win2019STIG']['stigrule_103565']['Title'] = "Windows Server 2019 password history must be configured to 24 passwords remembered."
default['Win2019STIG']['stigrule_103565']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103565']['Setting']['Enforce_password_history'] = 24

# R-103573 WN19-PK-000010
default['Win2019STIG']['stigrule_103573']['Manage'] = false
default['Win2019STIG']['stigrule_103573']['Title'] = "Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store."
default['Win2019STIG']['stigrule_103573']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Location'] = false
default['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Store'] = 'ROOT'
default['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Path'] = 'C:\Certificates\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561.cer'

default['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Location'] = false
default['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Store'] = 'ROOT'
default['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Path'] = 'C:\Certificates\D73CA91102A2204A36459ED32213B467D7CE97FB.cer'

default['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Location'] = false
default['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Store'] = 'ROOT'
default['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Path'] = 'C:\Certificates\B8269F25DBD937ECAFD4C35A9838571723F2D026.cer'

default['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Location'] = false
default['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Store'] = 'ROOT'
default['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Path'] = 'C:\Certificates\4ECB5CC3095670454DA1CBD410FC921F46B8564B.cer'

# R-103575 WN19-PK-000020
default['Win2019STIG']['stigrule_103575']['Manage'] = false
default['Win2019STIG']['stigrule_103575']['Title'] = "Windows Server 2019 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems."
default['Win2019STIG']['stigrule_103575']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Location'] = false
default['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Store'] = 'DISALLOWED'
default['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Path'] = 'C:\Certificates\22BBE981F0694D246CC1472ED2B021DC8540A22F.cer'

default['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Location'] = false
default['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Store'] = 'DISALLOWED'
default['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Path'] = 'C:\Certificates\FFAD03329B9E527A43EEC66A56F9CBB5393E6E13.cer'

default['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Location'] = false
default['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Store'] = 'DISALLOWED'
default['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Path'] = 'C:\Certificates\FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4.cer'

# R-103577 WN19-PK-000030
default['Win2019STIG']['stigrule_103577']['Manage'] = false
default['Win2019STIG']['stigrule_103577']['Title'] = "Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems."
default['Win2019STIG']['stigrule_103577']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Location'] = false
default['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Store'] = 'DISALLOWED'
default['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Path'] = 'C:\Certificates\DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3.cer'

default['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Location'] = false
default['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Store'] = 'DISALLOWED'
default['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Path'] = 'C:\Certificates\929BF3196896994C0A201DF4A5B71F603FEFBF2E.cer'

# R-103579 WN19-SO-000350
default['Win2019STIG']['stigrule_103579']['Manage'] = true
default['Win2019STIG']['stigrule_103579']['Title'] = "Windows Server 2019 users must be required to enter a password to access private keys stored on the computer."
default['Win2019STIG']['stigrule_103579']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103579']['Setting']['System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'] = 'User must enter a password each time they use a key'

# R-103583 WN19-SO-000010
default['Win2019STIG']['stigrule_103583']['Manage'] = true
default['Win2019STIG']['stigrule_103583']['Title'] = "Windows Server 2019 must have the built-in guest account disabled."
default['Win2019STIG']['stigrule_103583']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103583']['Setting']['Accounts_Guest_account_status'] = 'Disabled'

# R-103585 WN19-CC-000480
default['Win2019STIG']['stigrule_103585']['Manage'] = true
default['Win2019STIG']['stigrule_103585']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic."
default['Win2019STIG']['stigrule_103585']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
default['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_ValueType'] = :dword
default['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_ValueData'] = '0'
default['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_Ensure'] = :create

# R-103587 WN19-CC-000510
default['Win2019STIG']['stigrule_103587']['Manage'] = true
default['Win2019STIG']['stigrule_103587']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic."
default['Win2019STIG']['stigrule_103587']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
default['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_ValueType'] = :dword
default['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_ValueData'] = '0'
default['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_Ensure'] = :create

# R-103589 WN19-CC-000470
default['Win2019STIG']['stigrule_103589']['Manage'] = true
default['Win2019STIG']['stigrule_103589']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication."
default['Win2019STIG']['stigrule_103589']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
default['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_ValueType'] = :dword
default['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_ValueData'] = '0'
default['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_Ensure'] = :create

# R-103593 WN19-CC-000500
default['Win2019STIG']['stigrule_103593']['Manage'] = true
default['Win2019STIG']['stigrule_103593']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication."
default['Win2019STIG']['stigrule_103593']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
default['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_ValueType'] = :dword
default['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_ValueData'] = '0'
default['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_Ensure'] = :create

# R-103591 WN19-CC-000490
default['Win2019STIG']['stigrule_103591']['Manage'] = true
default['Win2019STIG']['stigrule_103591']['Title'] = "Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication."
default['Win2019STIG']['stigrule_103591']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
default['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_ValueType'] = :dword
default['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_ValueData'] = '0'
default['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_Ensure'] = :create

# R-103597 WN19-SO-000360
default['Win2019STIG']['stigrule_103597']['Manage'] = true
default['Win2019STIG']['stigrule_103597']['Title'] = "Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
default['Win2019STIG']['stigrule_103597']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103597']['Setting']['System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'] = 'Enabled'

# R-103603 WN19-CC-000240
default['Win2019STIG']['stigrule_103603']['Manage'] = true
default['Win2019STIG']['stigrule_103603']['Title'] = "Windows Server 2019 administrator accounts must not be enumerated during elevation."
default['Win2019STIG']['stigrule_103603']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
default['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_ValueType'] = :dword
default['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_ValueData'] = '0'
default['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_Ensure'] = :create

# R-103605 WN19-MS-000020
default['Win2019STIG']['stigrule_103605']['Manage'] = false
default['Win2019STIG']['stigrule_103605']['Title'] = "Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers."
default['Win2019STIG']['stigrule_103605']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
default['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_ValueType'] = :dword
default['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_ValueData'] = '0'
default['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_Ensure'] = :create

# R-103607 WN19-SO-000390
default['Win2019STIG']['stigrule_103607']['Manage'] = true
default['Win2019STIG']['stigrule_103607']['Title'] = "Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop."
default['Win2019STIG']['stigrule_103607']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103607']['Setting']['User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'] = 'Disabled'

# R-103609 WN19-SO-000400
default['Win2019STIG']['stigrule_103609']['Manage'] = true
default['Win2019STIG']['stigrule_103609']['Title'] = "Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop."
default['Win2019STIG']['stigrule_103609']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103609']['Setting']['User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'] = 'Prompt for consent on the secure desktop'

# R-103611 WN19-SO-000420
default['Win2019STIG']['stigrule_103611']['Manage'] = true
default['Win2019STIG']['stigrule_103611']['Title'] = "Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation."
default['Win2019STIG']['stigrule_103611']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103611']['Setting']['User_Account_Control_Detect_application_installations_and_prompt_for_elevation'] = 'Enabled'

# R-103613 WN19-SO-000430
default['Win2019STIG']['stigrule_103613']['Manage'] = true
default['Win2019STIG']['stigrule_103613']['Title'] = "Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations."
default['Win2019STIG']['stigrule_103613']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103613']['Setting']['User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'] = 'Enabled'

# R-103615 WN19-SO-000450
default['Win2019STIG']['stigrule_103615']['Manage'] = true
default['Win2019STIG']['stigrule_103615']['Title'] = "Windows Server 2019 User Account Control (UAC) must virtualize file and registry write failures to per-user locations."
default['Win2019STIG']['stigrule_103615']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103615']['Setting']['User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'] = 'Enabled'

# R-103619 WN19-CC-000350
default['Win2019STIG']['stigrule_103619']['Manage'] = true
default['Win2019STIG']['stigrule_103619']['Title'] = "Windows Server 2019 Remote Desktop Services must prevent drive redirection."
default['Win2019STIG']['stigrule_103619']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
default['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_ValueType'] = :dword
default['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_ValueData'] = '1'
default['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_Ensure'] = :create

# R-103623 WN19-SO-000230
default['Win2019STIG']['stigrule_103623']['Manage'] = true
default['Win2019STIG']['stigrule_103623']['Title'] = "Windows Server 2019 must not allow anonymous enumeration of shares."
default['Win2019STIG']['stigrule_103623']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103623']['Setting']['Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'] = 'Enabled'

# R-103625 WN19-SO-000250
default['Win2019STIG']['stigrule_103625']['Manage'] = true
default['Win2019STIG']['stigrule_103625']['Title'] = "Windows Server 2019 must restrict anonymous access to Named Pipes and Shares."
default['Win2019STIG']['stigrule_103625']['Severity'] = 'high'
default['Win2019STIG']['stigrule_103625']['Setting']['Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'] = 'Enabled'

# R-103627 WN19-CC-000060
default['Win2019STIG']['stigrule_103627']['Manage'] = true
default['Win2019STIG']['stigrule_103627']['Title'] = "Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers."
default['Win2019STIG']['stigrule_103627']['Severity'] = 'low'
default['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_Key'] = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
default['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_ValueType'] = :dword
default['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_ValueData'] = '1'
default['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_Ensure'] = :create

# R-103631 WN19-DC-000320
default['Win2019STIG']['stigrule_103631']['Manage'] = true
default['Win2019STIG']['stigrule_103631']['Title'] = "Windows Server 2019 domain controllers must require LDAP access signing."
default['Win2019STIG']['stigrule_103631']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103631']['Setting']['Domain_controller_LDAP_server_signing_requirements'] = 'Require signing'

# R-103633 WN19-SO-000060
default['Win2019STIG']['stigrule_103633']['Manage'] = true
default['Win2019STIG']['stigrule_103633']['Title'] = "Windows Server 2019 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled."
default['Win2019STIG']['stigrule_103633']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103633']['Setting']['Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'] = 'Enabled'

# R-103635 WN19-SO-000070
default['Win2019STIG']['stigrule_103635']['Manage'] = true
default['Win2019STIG']['stigrule_103635']['Title'] = "Windows Server 2019 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled."
default['Win2019STIG']['stigrule_103635']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103635']['Setting']['Domain_member_Digitally_encrypt_secure_channel_data_when_possible'] = 'Enabled'

# R-103637 WN19-SO-000080
default['Win2019STIG']['stigrule_103637']['Manage'] = true
default['Win2019STIG']['stigrule_103637']['Title'] = "Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled."
default['Win2019STIG']['stigrule_103637']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103637']['Setting']['Domain_member_Digitally_sign_secure_channel_data_when_possible'] = 'Enabled'

# R-103639 WN19-SO-000110
default['Win2019STIG']['stigrule_103639']['Manage'] = true
default['Win2019STIG']['stigrule_103639']['Title'] = "Windows Server 2019 must be configured to require a strong session key."
default['Win2019STIG']['stigrule_103639']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103639']['Setting']['Domain_member_Require_strong_Windows_2000_or_later_session_key'] = 'Enabled'

# R-103641 WN19-SO-000160
default['Win2019STIG']['stigrule_103641']['Manage'] = true
default['Win2019STIG']['stigrule_103641']['Title'] = "Windows Server 2019 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."
default['Win2019STIG']['stigrule_103641']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103641']['Setting']['Microsoft_network_client_Digitally_sign_communications_always'] = 'Enabled'

# R-103643 WN19-SO-000170
default['Win2019STIG']['stigrule_103643']['Manage'] = true
default['Win2019STIG']['stigrule_103643']['Title'] = "Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled."
default['Win2019STIG']['stigrule_103643']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103643']['Setting']['Microsoft_network_client_Digitally_sign_communications_if_server_agrees'] = 'Enabled'

# R-103645 WN19-SO-000190
default['Win2019STIG']['stigrule_103645']['Manage'] = true
default['Win2019STIG']['stigrule_103645']['Title'] = "Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."
default['Win2019STIG']['stigrule_103645']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103645']['Setting']['Microsoft_network_server_Digitally_sign_communications_always'] = 'Enabled'

# R-103647 WN19-SO-000200
default['Win2019STIG']['stigrule_103647']['Manage'] = true
default['Win2019STIG']['stigrule_103647']['Title'] = "Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."
default['Win2019STIG']['stigrule_103647']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103647']['Setting']['Microsoft_network_server_Digitally_sign_communications_if_client_agrees'] = 'Enabled'

# R-103649 WN19-CC-000310
default['Win2019STIG']['stigrule_103649']['Manage'] = true
default['Win2019STIG']['stigrule_103649']['Title'] = "Windows Server 2019 Explorer Data Execution Prevention must be enabled."
default['Win2019STIG']['stigrule_103649']['Severity'] = 'medium'
default['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_Key'] = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
default['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_ValueType'] = :dword
default['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_ValueData'] = '0'
default['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_Ensure'] = :create

