include_recipe 'windows::default'

powershell_package "PowerShellGet" do
  version "1.6.6"
  source node['Win2019STIG']['powershell_package_Source']
end
powershell_package "AuditPolicyDsc" do
  version "1.2.0.0"
  source node['Win2019STIG']['powershell_package_Source']
end
powershell_package "SecurityPolicyDsc" do
  version "2.4.0.0"
  source node['Win2019STIG']['powershell_package_Source']
end
if node['Win2019STIG']['stigrule_103049']['Manage']
  dsc_resource 'Interactive_logon_Machine_inactivity_limit_103049' do
    resource :SecurityOption
    property :name, 'Interactive_logon_Machine_inactivity_limit'
    property :Interactive_logon_Machine_inactivity_limit, node['Win2019STIG']['stigrule_103049']['Setting']['Interactive_logon_Machine_inactivity_limit']
  end
end
if node['Win2019STIG']['stigrule_103051']['Manage']
  dsc_resource 'Deny_log_on_through_Remote_Desktop_Services_103051' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_through_Remote_Desktop_Services'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103051']['Setting']['Deny_log_on_through_Remote_Desktop_Services_Identity']
  end
end
if node['Win2019STIG']['stigrule_103053']['Manage']
  dsc_resource 'Deny_log_on_through_Remote_Desktop_Services_103053' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_through_Remote_Desktop_Services'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103053']['Setting']['Deny_log_on_through_Remote_Desktop_Services_Identity']
  end
end
if node['Win2019STIG']['stigrule_103055']['Manage']
  dsc_resource 'Logon_103055' do
    resource :AuditPolicySubcategory
    property :name, 'Logon'
    property :AuditFlag, node['Win2019STIG']['stigrule_103055']['Setting']['Logon_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103055']['Setting']['Logon_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103057']['Manage']
  dsc_resource 'Logon_103057' do
    resource :AuditPolicySubcategory
    property :name, 'Logon'
    property :AuditFlag, node['Win2019STIG']['stigrule_103057']['Setting']['Logon_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103057']['Setting']['Logon_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103059']['Manage']
  registry_key 'fEncryptRPCTraffic_103059' do
    key node['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_Key']
    values [{
      name: 'fEncryptRPCTraffic',
      type: node['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_ValueType'],
      data: node['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103059']['Setting']['fEncryptRPCTraffic_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103061']['Manage']
  registry_key 'MinEncryptionLevel_103061' do
    key node['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_Key']
    values [{
      name: 'MinEncryptionLevel',
      type: node['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_ValueType'],
      data: node['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103061']['Setting']['MinEncryptionLevel_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103067']['Manage']
  dsc_resource 'Security_Group_Management_103067' do
    resource :AuditPolicySubcategory
    property :name, 'Security Group Management'
    property :AuditFlag, node['Win2019STIG']['stigrule_103067']['Setting']['Security_Group_Management_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103067']['Setting']['Security_Group_Management_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103069']['Manage']
  dsc_resource 'User_Account_Management_103069' do
    resource :AuditPolicySubcategory
    property :name, 'User Account Management'
    property :AuditFlag, node['Win2019STIG']['stigrule_103069']['Setting']['User_Account_Management_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103069']['Setting']['User_Account_Management_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103071']['Manage']
  dsc_resource 'User_Account_Management_103071' do
    resource :AuditPolicySubcategory
    property :name, 'User Account Management'
    property :AuditFlag, node['Win2019STIG']['stigrule_103071']['Setting']['User_Account_Management_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103071']['Setting']['User_Account_Management_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103073']['Manage']
  dsc_resource 'Computer_Account_Management_103073' do
    resource :AuditPolicySubcategory
    property :name, 'Computer Account Management'
    property :AuditFlag, node['Win2019STIG']['stigrule_103073']['Setting']['Computer_Account_Management_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103073']['Setting']['Computer_Account_Management_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103075']['Manage']
  dsc_resource 'Account_Lockout_103075' do
    resource :AuditPolicySubcategory
    property :name, 'Account Lockout'
    property :AuditFlag, node['Win2019STIG']['stigrule_103075']['Setting']['Account_Lockout_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103075']['Setting']['Account_Lockout_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103077']['Manage']
  dsc_resource 'Account_Lockout_103077' do
    resource :AuditPolicySubcategory
    property :name, 'Account Lockout'
    property :AuditFlag, node['Win2019STIG']['stigrule_103077']['Setting']['Account_Lockout_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103077']['Setting']['Account_Lockout_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103083']['Manage']
  dsc_resource 'Access_this_computer_from_the_network_103083' do
    resource :UserRightsAssignment
    property :Policy, 'Access_this_computer_from_the_network'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103083']['Setting']['Access_this_computer_from_the_network_Identity']
  end
end
if node['Win2019STIG']['stigrule_103095']['Manage']
  dsc_resource 'Access_this_computer_from_the_network_103095' do
    resource :UserRightsAssignment
    property :Policy, 'Access_this_computer_from_the_network'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103095']['Setting']['Access_this_computer_from_the_network_Identity']
  end
end
if node['Win2019STIG']['stigrule_103085']['Manage']
  dsc_resource 'Allow_log_on_through_Remote_Desktop_Services_103085' do
    resource :UserRightsAssignment
    property :Policy, 'Allow_log_on_through_Remote_Desktop_Services'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103085']['Setting']['Allow_log_on_through_Remote_Desktop_Services_Identity']
  end
end
if node['Win2019STIG']['stigrule_103087']['Manage']
  dsc_resource 'Deny_access_to_this_computer_from_the_network_103087' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_access_to_this_computer_from_the_network'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103087']['Setting']['Deny_access_to_this_computer_from_the_network_Identity']
  end
end
if node['Win2019STIG']['stigrule_103097']['Manage']
  dsc_resource 'Deny_access_to_this_computer_from_the_network_103097' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_access_to_this_computer_from_the_network'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103097']['Setting']['Deny_access_to_this_computer_from_the_network_Identity']
  end
end
if node['Win2019STIG']['stigrule_103089']['Manage']
  dsc_resource 'Deny_log_on_as_a_batch_job_103089' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_as_a_batch_job'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103089']['Setting']['Deny_log_on_as_a_batch_job_Identity']
  end
end
if node['Win2019STIG']['stigrule_103099']['Manage']
  dsc_resource 'Deny_log_on_as_a_batch_job_103099' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_as_a_batch_job'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103099']['Setting']['Deny_log_on_as_a_batch_job_Identity']
  end
end
if node['Win2019STIG']['stigrule_103091']['Manage']
  dsc_resource 'Deny_log_on_as_a_service_103091' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_as_a_service'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103091']['Setting']['Deny_log_on_as_a_service_Identity']
  end
end
if node['Win2019STIG']['stigrule_103101']['Manage']
  dsc_resource 'Deny_log_on_as_a_service_103101' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_as_a_service'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103101']['Setting']['Deny_log_on_as_a_service_Identity']
  end
end
if node['Win2019STIG']['stigrule_103093']['Manage']
  dsc_resource 'Deny_log_on_locally_103093' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_locally'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103093']['Setting']['Deny_log_on_locally_Identity']
  end
end
if node['Win2019STIG']['stigrule_103103']['Manage']
  dsc_resource 'Deny_log_on_locally_103103' do
    resource :UserRightsAssignment
    property :Policy, 'Deny_log_on_locally'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103103']['Setting']['Deny_log_on_locally_Identity']
  end
end
if node['Win2019STIG']['stigrule_103105']['Manage']
  dsc_resource 'Allow_log_on_locally_103105' do
    resource :UserRightsAssignment
    property :Policy, 'Allow_log_on_locally'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103105']['Setting']['Allow_log_on_locally_Identity']
  end
end
if node['Win2019STIG']['stigrule_103127']['Manage']
  dsc_resource 'Add_workstations_to_domain_103127' do
    resource :UserRightsAssignment
    property :Policy, 'Add_workstations_to_domain'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103127']['Setting']['Add_workstations_to_domain_Identity']
  end
end
if node['Win2019STIG']['stigrule_103129']['Manage']
  dsc_resource 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation_103129' do
    resource :UserRightsAssignment
    property :Policy, 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103129']['Setting']['Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity']
  end
end
if node['Win2019STIG']['stigrule_103135']['Manage']
  dsc_resource 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation_103135' do
    resource :UserRightsAssignment
    property :Policy, 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103135']['Setting']['Enable_computer_and_user_accounts_to_be_trusted_for_delegation_Identity']
  end
end
if node['Win2019STIG']['stigrule_103137']['Manage']
  dsc_resource 'Access_Credential_Manager_as_a_trusted_caller_103137' do
    resource :UserRightsAssignment
    property :Policy, 'Access_Credential_Manager_as_a_trusted_caller'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103137']['Setting']['Access_Credential_Manager_as_a_trusted_caller_Identity']
  end
end
if node['Win2019STIG']['stigrule_103139']['Manage']
  dsc_resource 'Act_as_part_of_the_operating_system_103139' do
    resource :UserRightsAssignment
    property :Policy, 'Act_as_part_of_the_operating_system'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103139']['Setting']['Act_as_part_of_the_operating_system_Identity']
  end
end
if node['Win2019STIG']['stigrule_103141']['Manage']
  dsc_resource 'Back_up_files_and_directories_103141' do
    resource :UserRightsAssignment
    property :Policy, 'Back_up_files_and_directories'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103141']['Setting']['Back_up_files_and_directories_Identity']
  end
end
if node['Win2019STIG']['stigrule_103143']['Manage']
  dsc_resource 'Create_a_pagefile_103143' do
    resource :UserRightsAssignment
    property :Policy, 'Create_a_pagefile'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103143']['Setting']['Create_a_pagefile_Identity']
  end
end
if node['Win2019STIG']['stigrule_103145']['Manage']
  dsc_resource 'Create_a_token_object_103145' do
    resource :UserRightsAssignment
    property :Policy, 'Create_a_token_object'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103145']['Setting']['Create_a_token_object_Identity']
  end
end
if node['Win2019STIG']['stigrule_103147']['Manage']
  dsc_resource 'Create_global_objects_103147' do
    resource :UserRightsAssignment
    property :Policy, 'Create_global_objects'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103147']['Setting']['Create_global_objects_Identity']
  end
end
if node['Win2019STIG']['stigrule_103149']['Manage']
  dsc_resource 'Create_permanent_shared_objects_103149' do
    resource :UserRightsAssignment
    property :Policy, 'Create_permanent_shared_objects'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103149']['Setting']['Create_permanent_shared_objects_Identity']
  end
end
if node['Win2019STIG']['stigrule_103151']['Manage']
  dsc_resource 'Create_symbolic_links_103151' do
    resource :UserRightsAssignment
    property :Policy, 'Create_symbolic_links'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103151']['Setting']['Create_symbolic_links_Identity']
  end
end
if node['Win2019STIG']['stigrule_103153']['Manage']
  dsc_resource 'Debug_programs_103153' do
    resource :UserRightsAssignment
    property :Policy, 'Debug_programs'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103153']['Setting']['Debug_programs_Identity']
  end
end
if node['Win2019STIG']['stigrule_103155']['Manage']
  dsc_resource 'Force_shutdown_from_a_remote_system_103155' do
    resource :UserRightsAssignment
    property :Policy, 'Force_shutdown_from_a_remote_system'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103155']['Setting']['Force_shutdown_from_a_remote_system_Identity']
  end
end
if node['Win2019STIG']['stigrule_103157']['Manage']
  dsc_resource 'Generate_security_audits_103157' do
    resource :UserRightsAssignment
    property :Policy, 'Generate_security_audits'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103157']['Setting']['Generate_security_audits_Identity']
  end
end
if node['Win2019STIG']['stigrule_103159']['Manage']
  dsc_resource 'Impersonate_a_client_after_authentication_103159' do
    resource :UserRightsAssignment
    property :Policy, 'Impersonate_a_client_after_authentication'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103159']['Setting']['Impersonate_a_client_after_authentication_Identity']
  end
end
if node['Win2019STIG']['stigrule_103161']['Manage']
  dsc_resource 'Increase_scheduling_priority_103161' do
    resource :UserRightsAssignment
    property :Policy, 'Increase_scheduling_priority'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103161']['Setting']['Increase_scheduling_priority_Identity']
  end
end
if node['Win2019STIG']['stigrule_103163']['Manage']
  dsc_resource 'Load_and_unload_device_drivers_103163' do
    resource :UserRightsAssignment
    property :Policy, 'Load_and_unload_device_drivers'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103163']['Setting']['Load_and_unload_device_drivers_Identity']
  end
end
if node['Win2019STIG']['stigrule_103165']['Manage']
  dsc_resource 'Lock_pages_in_memory_103165' do
    resource :UserRightsAssignment
    property :Policy, 'Lock_pages_in_memory'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103165']['Setting']['Lock_pages_in_memory_Identity']
  end
end
if node['Win2019STIG']['stigrule_103167']['Manage']
  dsc_resource 'Modify_firmware_environment_values_103167' do
    resource :UserRightsAssignment
    property :Policy, 'Modify_firmware_environment_values'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103167']['Setting']['Modify_firmware_environment_values_Identity']
  end
end
if node['Win2019STIG']['stigrule_103169']['Manage']
  dsc_resource 'Perform_volume_maintenance_tasks_103169' do
    resource :UserRightsAssignment
    property :Policy, 'Perform_volume_maintenance_tasks'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103169']['Setting']['Perform_volume_maintenance_tasks_Identity']
  end
end
if node['Win2019STIG']['stigrule_103171']['Manage']
  dsc_resource 'Profile_single_process_103171' do
    resource :UserRightsAssignment
    property :Policy, 'Profile_single_process'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103171']['Setting']['Profile_single_process_Identity']
  end
end
if node['Win2019STIG']['stigrule_103173']['Manage']
  dsc_resource 'Restore_files_and_directories_103173' do
    resource :UserRightsAssignment
    property :Policy, 'Restore_files_and_directories'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103173']['Setting']['Restore_files_and_directories_Identity']
  end
end
if node['Win2019STIG']['stigrule_103175']['Manage']
  dsc_resource 'Take_ownership_of_files_or_other_objects_103175' do
    resource :UserRightsAssignment
    property :Policy, 'Take_ownership_of_files_or_other_objects'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103175']['Setting']['Take_ownership_of_files_or_other_objects_Identity']
  end
end
if node['Win2019STIG']['stigrule_103177']['Manage']
  dsc_resource 'Other_Account_Management_Events_103177' do
    resource :AuditPolicySubcategory
    property :name, 'Other Account Management Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103177']['Setting']['Other_Account_Management_Events_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103177']['Setting']['Other_Account_Management_Events_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103179']['Manage']
  dsc_resource 'Process_Creation_103179' do
    resource :AuditPolicySubcategory
    property :name, 'Process Creation'
    property :AuditFlag, node['Win2019STIG']['stigrule_103179']['Setting']['Process_Creation_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103179']['Setting']['Process_Creation_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103181']['Manage']
  dsc_resource 'Policy_Change_103181' do
    resource :AuditPolicySubcategory
    property :name, 'Audit Policy Change'
    property :AuditFlag, node['Win2019STIG']['stigrule_103181']['Setting']['Policy_Change_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103181']['Setting']['Policy_Change_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103183']['Manage']
  dsc_resource 'Policy_Change_103183' do
    resource :AuditPolicySubcategory
    property :name, 'Audit Policy Change'
    property :AuditFlag, node['Win2019STIG']['stigrule_103183']['Setting']['Policy_Change_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103183']['Setting']['Policy_Change_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103185']['Manage']
  dsc_resource 'Authentication_Policy_Change_103185' do
    resource :AuditPolicySubcategory
    property :name, 'Authentication Policy Change'
    property :AuditFlag, node['Win2019STIG']['stigrule_103185']['Setting']['Authentication_Policy_Change_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103185']['Setting']['Authentication_Policy_Change_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103187']['Manage']
  dsc_resource 'Authorization_Policy_Change_103187' do
    resource :AuditPolicySubcategory
    property :name, 'Authorization Policy Change'
    property :AuditFlag, node['Win2019STIG']['stigrule_103187']['Setting']['Authorization_Policy_Change_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103187']['Setting']['Authorization_Policy_Change_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103189']['Manage']
  dsc_resource 'Sensitive_Privilege_Use_103189' do
    resource :AuditPolicySubcategory
    property :name, 'Sensitive Privilege Use'
    property :AuditFlag, node['Win2019STIG']['stigrule_103189']['Setting']['Sensitive_Privilege_Use_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103189']['Setting']['Sensitive_Privilege_Use_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103191']['Manage']
  dsc_resource 'Sensitive_Privilege_Use_103191' do
    resource :AuditPolicySubcategory
    property :name, 'Sensitive Privilege Use'
    property :AuditFlag, node['Win2019STIG']['stigrule_103191']['Setting']['Sensitive_Privilege_Use_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103191']['Setting']['Sensitive_Privilege_Use_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103193']['Manage']
  dsc_resource 'IPsec_Driver_103193' do
    resource :AuditPolicySubcategory
    property :name, 'IPsec Driver'
    property :AuditFlag, node['Win2019STIG']['stigrule_103193']['Setting']['IPsec_Driver_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103193']['Setting']['IPsec_Driver_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103195']['Manage']
  dsc_resource 'IPsec_Driver_103195' do
    resource :AuditPolicySubcategory
    property :name, 'IPsec Driver'
    property :AuditFlag, node['Win2019STIG']['stigrule_103195']['Setting']['IPsec_Driver_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103195']['Setting']['IPsec_Driver_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103197']['Manage']
  dsc_resource 'Other_System_Events_103197' do
    resource :AuditPolicySubcategory
    property :name, 'Other System Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103197']['Setting']['Other_System_Events_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103197']['Setting']['Other_System_Events_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103199']['Manage']
  dsc_resource 'Other_System_Events_103199' do
    resource :AuditPolicySubcategory
    property :name, 'Other System Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103199']['Setting']['Other_System_Events_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103199']['Setting']['Other_System_Events_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103201']['Manage']
  dsc_resource 'Security_State_Change_103201' do
    resource :AuditPolicySubcategory
    property :name, 'Security State Change'
    property :AuditFlag, node['Win2019STIG']['stigrule_103201']['Setting']['Security_State_Change_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103201']['Setting']['Security_State_Change_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103203']['Manage']
  dsc_resource 'Security_System_Extension_103203' do
    resource :AuditPolicySubcategory
    property :name, 'Security System Extension'
    property :AuditFlag, node['Win2019STIG']['stigrule_103203']['Setting']['Security_System_Extension_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103203']['Setting']['Security_System_Extension_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103205']['Manage']
  dsc_resource 'System_Integrity_103205' do
    resource :AuditPolicySubcategory
    property :name, 'System Integrity'
    property :AuditFlag, node['Win2019STIG']['stigrule_103205']['Setting']['System_Integrity_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103205']['Setting']['System_Integrity_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103207']['Manage']
  dsc_resource 'System_Integrity_103207' do
    resource :AuditPolicySubcategory
    property :name, 'System Integrity'
    property :AuditFlag, node['Win2019STIG']['stigrule_103207']['Setting']['System_Integrity_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103207']['Setting']['System_Integrity_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103221']['Manage']
  dsc_resource 'Directory_Service_Access_103221' do
    resource :AuditPolicySubcategory
    property :name, 'Directory Service Access'
    property :AuditFlag, node['Win2019STIG']['stigrule_103221']['Setting']['Directory_Service_Access_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103221']['Setting']['Directory_Service_Access_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103223']['Manage']
  dsc_resource 'Directory_Service_Access_103223' do
    resource :AuditPolicySubcategory
    property :name, 'Directory Service Access'
    property :AuditFlag, node['Win2019STIG']['stigrule_103223']['Setting']['Directory_Service_Access_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103223']['Setting']['Directory_Service_Access_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103225']['Manage']
  dsc_resource 'Directory_Service_Changes_103225' do
    resource :AuditPolicySubcategory
    property :name, 'Directory Service Changes'
    property :AuditFlag, node['Win2019STIG']['stigrule_103225']['Setting']['Directory_Service_Changes_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103225']['Setting']['Directory_Service_Changes_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103227']['Manage']
  dsc_resource 'Directory_Service_Changes_103227' do
    resource :AuditPolicySubcategory
    property :name, 'Directory Service Changes'
    property :AuditFlag, node['Win2019STIG']['stigrule_103227']['Setting']['Directory_Service_Changes_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103227']['Setting']['Directory_Service_Changes_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103229']['Manage']
  dsc_resource 'Account_lockout_threshold_103229' do
    resource :AccountPolicy
    property :name, 'Account_lockout_threshold'
    property :Account_lockout_threshold, node['Win2019STIG']['stigrule_103229']['Setting']['Account_lockout_threshold']
  end
end
if node['Win2019STIG']['stigrule_103231']['Manage']
  dsc_resource 'Reset_account_lockout_counter_after_103231' do
    resource :AccountPolicy
    property :name, 'Reset_account_lockout_counter_after'
    property :Reset_account_lockout_counter_after, node['Win2019STIG']['stigrule_103231']['Setting']['Reset_account_lockout_counter_after']
    notifies :run, 'dsc_resource[Account_lockout_threshold_103229]', :before
  end
end
if node['Win2019STIG']['stigrule_103233']['Manage']
  dsc_resource 'Account_lockout_duration_103233' do
    resource :AccountPolicy
    property :name, 'Account_lockout_duration'
    property :Account_lockout_duration, node['Win2019STIG']['stigrule_103233']['Setting']['Account_lockout_duration']
    notifies :run, 'dsc_resource[Reset_account_lockout_counter_after_103231]', :before
  end
end
if node['Win2019STIG']['stigrule_103235']['Manage']
  dsc_resource 'Interactive_logon_Message_text_for_users_attempting_to_log_on_103235' do
    resource :SecurityOption
    property :name, 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
    property :Interactive_logon_Message_text_for_users_attempting_to_log_on, node['Win2019STIG']['stigrule_103235']['Setting']['Interactive_logon_Message_text_for_users_attempting_to_log_on']
  end
end
if node['Win2019STIG']['stigrule_103237']['Manage']
  dsc_resource 'Interactive_logon_Message_title_for_users_attempting_to_log_on_103237' do
    resource :SecurityOption
    property :name, 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
    property :Interactive_logon_Message_title_for_users_attempting_to_log_on, node['Win2019STIG']['stigrule_103237']['Setting']['Interactive_logon_Message_title_for_users_attempting_to_log_on']
  end
end
if node['Win2019STIG']['stigrule_103239']['Manage']
  dsc_resource 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_103239' do
    resource :SecurityOption
    property :name, 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
    property :Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings, node['Win2019STIG']['stigrule_103239']['Setting']['Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings']
  end
end
if node['Win2019STIG']['stigrule_103241']['Manage']
  dsc_resource 'Credential_Validation_103241' do
    resource :AuditPolicySubcategory
    property :name, 'Credential Validation'
    property :AuditFlag, node['Win2019STIG']['stigrule_103241']['Setting']['Credential_Validation_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103241']['Setting']['Credential_Validation_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103243']['Manage']
  dsc_resource 'Credential_Validation_103243' do
    resource :AuditPolicySubcategory
    property :name, 'Credential Validation'
    property :AuditFlag, node['Win2019STIG']['stigrule_103243']['Setting']['Credential_Validation_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103243']['Setting']['Credential_Validation_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103245']['Manage']
  dsc_resource 'PNP_Activity_103245' do
    resource :AuditPolicySubcategory
    property :name, 'Plug and Play Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103245']['Setting']['PNP_Activity_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103245']['Setting']['PNP_Activity_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103247']['Manage']
  dsc_resource 'Group_Membership_103247' do
    resource :AuditPolicySubcategory
    property :name, 'Group Membership'
    property :AuditFlag, node['Win2019STIG']['stigrule_103247']['Setting']['Group_Membership_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103247']['Setting']['Group_Membership_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103249']['Manage']
  dsc_resource 'Special_Logon_103249' do
    resource :AuditPolicySubcategory
    property :name, 'Special Logon'
    property :AuditFlag, node['Win2019STIG']['stigrule_103249']['Setting']['Special_Logon_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103249']['Setting']['Special_Logon_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103251']['Manage']
  dsc_resource 'Other_Object_Access_Events_103251' do
    resource :AuditPolicySubcategory
    property :name, 'Other Object Access Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103251']['Setting']['Other_Object_Access_Events_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103251']['Setting']['Other_Object_Access_Events_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103253']['Manage']
  dsc_resource 'Other_Object_Access_Events_103253' do
    resource :AuditPolicySubcategory
    property :name, 'Other Object Access Events'
    property :AuditFlag, node['Win2019STIG']['stigrule_103253']['Setting']['Other_Object_Access_Events_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103253']['Setting']['Other_Object_Access_Events_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103255']['Manage']
  dsc_resource 'Removable_Storage_103255' do
    resource :AuditPolicySubcategory
    property :name, 'Removable Storage'
    property :AuditFlag, node['Win2019STIG']['stigrule_103255']['Setting']['Removable_Storage_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103255']['Setting']['Removable_Storage_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103257']['Manage']
  dsc_resource 'Removable_Storage_103257' do
    resource :AuditPolicySubcategory
    property :name, 'Removable Storage'
    property :AuditFlag, node['Win2019STIG']['stigrule_103257']['Setting']['Removable_Storage_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103257']['Setting']['Removable_Storage_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103259']['Manage']
  dsc_resource 'Logoff_103259' do
    resource :AuditPolicySubcategory
    property :name, 'Logoff'
    property :AuditFlag, node['Win2019STIG']['stigrule_103259']['Setting']['Logoff_AuditFlag']
    property :Ensure, node['Win2019STIG']['stigrule_103259']['Setting']['Logoff_Ensure']
  end
end
if node['Win2019STIG']['stigrule_103261']['Manage']
  registry_key 'ProcessCreationIncludeCmdLine_Enabled_103261' do
    key node['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_Key']
    values [{
      name: 'ProcessCreationIncludeCmdLine_Enabled',
      type: node['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_ValueType'],
      data: node['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103261']['Setting']['ProcessCreationIncludeCmdLine_Enabled_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103263']['Manage']
  registry_key 'EnableScriptBlockLogging_103263' do
    key node['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_Key']
    values [{
      name: 'EnableScriptBlockLogging',
      type: node['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_ValueType'],
      data: node['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103263']['Setting']['EnableScriptBlockLogging_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103265']['Manage']
  registry_key 'MaxSize_103265' do
    key node['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_Key']
    values [{
      name: 'MaxSize',
      type: node['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_ValueType'],
      data: node['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103265']['Setting']['MaxSize_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103267']['Manage']
  registry_key 'MaxSize_103267' do
    key node['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_Key']
    values [{
      name: 'MaxSize',
      type: node['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_ValueType'],
      data: node['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103267']['Setting']['MaxSize_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103269']['Manage']
  registry_key 'MaxSize_103269' do
    key node['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_Key']
    values [{
      name: 'MaxSize',
      type: node['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_ValueType'],
      data: node['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103269']['Setting']['MaxSize_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'NtpServer_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_Key']
    values [{
      name: 'NtpServer',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['NtpServer_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'Type_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['Type_Key']
    values [{
      name: 'Type',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['Type_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['Type_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['Type_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'CrossSiteSyncFlags_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_Key']
    values [{
      name: 'CrossSiteSyncFlags',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['CrossSiteSyncFlags_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'EventLogFlags_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_Key']
    values [{
      name: 'EventLogFlags',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['EventLogFlags_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'ResolvePeerBackoffMaxTimes_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_Key']
    values [{
      name: 'ResolvePeerBackoffMaxTimes',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMaxTimes_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'ResolvePeerBackoffMinutes_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_Key']
    values [{
      name: 'ResolvePeerBackoffMinutes',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['ResolvePeerBackoffMinutes_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103275']['Manage']
  registry_key 'SpecialPollInterval_103275' do
    key node['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_Key']
    values [{
      name: 'SpecialPollInterval',
      type: node['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_ValueType'],
      data: node['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103275']['Setting']['SpecialPollInterval_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103277']['Manage']
  file 'C__Windows_System32_winevt_Logs_Application_evtx_103277' do
    path node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Path']
    inherits node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Inherits']
    rights node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_1'], node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_1']
    rights node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_2'], node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_2']
    rights node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Permission_3'], node['Win2019STIG']['stigrule_103277']['Setting']['C__Windows_System32_winevt_Logs_Application_evtx_Principal_3']
  end
end
if node['Win2019STIG']['stigrule_103279']['Manage']
  file 'C__Windows_System32_winevt_Logs_Security_evtx_103279' do
    path node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Path']
    inherits node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Inherits']
    rights node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_1'], node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_1']
    rights node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_2'], node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_2']
    rights node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Permission_3'], node['Win2019STIG']['stigrule_103279']['Setting']['C__Windows_System32_winevt_Logs_Security_evtx_Principal_3']
  end
end
if node['Win2019STIG']['stigrule_103281']['Manage']
  file 'C__Windows_System32_winevt_Logs_System_evtx_103281' do
    path node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Path']
    inherits node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Inherits']
    rights node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_1'], node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_1']
    rights node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_2'], node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_2']
    rights node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Permission_3'], node['Win2019STIG']['stigrule_103281']['Setting']['C__Windows_System32_winevt_Logs_System_evtx_Principal_3']
  end
end
if node['Win2019STIG']['stigrule_103285']['Manage']
  dsc_resource 'Manage_auditing_and_security_log_103285' do
    resource :UserRightsAssignment
    property :Policy, 'Manage_auditing_and_security_log'
    property :Force, true
    property :Identity, node['Win2019STIG']['stigrule_103285']['Setting']['Manage_auditing_and_security_log_Identity']
  end
end
if node['Win2019STIG']['stigrule_103287']['Manage']
  registry_key 'EnableUserControl_103287' do
    key node['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_Key']
    values [{
      name: 'EnableUserControl',
      type: node['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_ValueType'],
      data: node['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103287']['Setting']['EnableUserControl_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103289']['Manage']
  registry_key 'AlwaysInstallElevated_103289' do
    key node['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_Key']
    values [{
      name: 'AlwaysInstallElevated',
      type: node['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_ValueType'],
      data: node['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103289']['Setting']['AlwaysInstallElevated_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103321']['Manage']
  registry_key 'DisableIPSourceRouting_103321' do
    key node['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_Key']
    values [{
      name: 'DisableIPSourceRouting',
      type: node['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_ValueType'],
      data: node['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103321']['Setting']['DisableIPSourceRouting_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103323']['Manage']
  registry_key 'DisableIPSourceRouting_103323' do
    key node['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_Key']
    values [{
      name: 'DisableIPSourceRouting',
      type: node['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_ValueType'],
      data: node['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103323']['Setting']['DisableIPSourceRouting_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103325']['Manage']
  registry_key 'EnableICMPRedirect_103325' do
    key node['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_Key']
    values [{
      name: 'EnableICMPRedirect',
      type: node['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_ValueType'],
      data: node['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103325']['Setting']['EnableICMPRedirect_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103327']['Manage']
  registry_key 'AllowInsecureGuestAuth_103327' do
    key node['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_Key']
    values [{
      name: 'AllowInsecureGuestAuth',
      type: node['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_ValueType'],
      data: node['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103327']['Setting']['AllowInsecureGuestAuth_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103329']['Manage']
  registry_key '____NETLOGON_103329' do
    key node['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_Key']
    values [{
      name: '\\*\NETLOGON',
      type: node['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_ValueType'],
      data: node['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103329']['Setting']['____NETLOGON_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103329']['Manage']
  registry_key '____SYSVOL_103329' do
    key node['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_Key']
    values [{
      name: '\\*\SYSVOL',
      type: node['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_ValueType'],
      data: node['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103329']['Setting']['____SYSVOL_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103331']['Manage']
  registry_key 'AllowProtectedCreds_103331' do
    key node['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_Key']
    values [{
      name: 'AllowProtectedCreds',
      type: node['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_ValueType'],
      data: node['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103331']['Setting']['AllowProtectedCreds_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103333']['Manage']
  registry_key 'EnableVirtualizationBasedSecurity_103333' do
    key node['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_Key']
    values [{
      name: 'EnableVirtualizationBasedSecurity',
      type: node['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_ValueType'],
      data: node['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103333']['Setting']['EnableVirtualizationBasedSecurity_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103333']['Manage']
  registry_key 'RequirePlatformSecurityFeatures_103333' do
    key node['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_Key']
    values [{
      name: 'RequirePlatformSecurityFeatures',
      type: node['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_ValueType'],
      data: node['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103333']['Setting']['RequirePlatformSecurityFeatures_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103337']['Manage']
  registry_key 'DriverLoadPolicy_103337' do
    key node['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_Key']
    values [{
      name: 'DriverLoadPolicy',
      type: node['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_ValueType'],
      data: node['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103337']['Setting']['DriverLoadPolicy_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103339']['Manage']
  registry_key 'NoGPOListChanges_103339' do
    key node['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_Key']
    values [{
      name: 'NoGPOListChanges',
      type: node['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_ValueType'],
      data: node['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103339']['Setting']['NoGPOListChanges_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103341']['Manage']
  registry_key 'DCSettingIndex_103341' do
    key node['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_Key']
    values [{
      name: 'DCSettingIndex',
      type: node['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_ValueType'],
      data: node['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103341']['Setting']['DCSettingIndex_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103343']['Manage']
  registry_key 'ACSettingIndex_103343' do
    key node['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_Key']
    values [{
      name: 'ACSettingIndex',
      type: node['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_ValueType'],
      data: node['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103343']['Setting']['ACSettingIndex_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103345']['Manage']
  registry_key 'AllowTelemetry_103345' do
    key node['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_Key']
    values [{
      name: 'AllowTelemetry',
      type: node['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_ValueType'],
      data: node['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103345']['Setting']['AllowTelemetry_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103347']['Manage']
  registry_key 'DODownloadMode_103347' do
    key node['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_Key']
    values [{
      name: 'DODownloadMode',
      type: node['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_ValueType'],
      data: node['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103347']['Setting']['DODownloadMode_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103349']['Manage']
  registry_key 'NoHeapTerminationOnCorruption_103349' do
    key node['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_Key']
    values [{
      name: 'NoHeapTerminationOnCorruption',
      type: node['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_ValueType'],
      data: node['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103349']['Setting']['NoHeapTerminationOnCorruption_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103351']['Manage']
  registry_key 'PreXPSP2ShellProtocolBehavior_103351' do
    key node['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_Key']
    values [{
      name: 'PreXPSP2ShellProtocolBehavior',
      type: node['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_ValueType'],
      data: node['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103351']['Setting']['PreXPSP2ShellProtocolBehavior_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103353']['Manage']
  registry_key 'DisableEnclosureDownload_103353' do
    key node['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_Key']
    values [{
      name: 'DisableEnclosureDownload',
      type: node['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_ValueType'],
      data: node['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103353']['Setting']['DisableEnclosureDownload_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103355']['Manage']
  registry_key 'SafeForScripting_103355' do
    key node['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_Key']
    values [{
      name: 'SafeForScripting',
      type: node['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_ValueType'],
      data: node['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103355']['Setting']['SafeForScripting_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103357']['Manage']
  registry_key 'DisableAutomaticRestartSignOn_103357' do
    key node['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_Key']
    values [{
      name: 'DisableAutomaticRestartSignOn',
      type: node['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_ValueType'],
      data: node['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103357']['Setting']['DisableAutomaticRestartSignOn_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103361']['Manage']
  dsc_resource 'Domain_controller_Refuse_machine_account_password_changes_103361' do
    resource :SecurityOption
    property :name, 'Domain_controller_Refuse_machine_account_password_changes'
    property :Domain_controller_Refuse_machine_account_password_changes, node['Win2019STIG']['stigrule_103361']['Setting']['Domain_controller_Refuse_machine_account_password_changes']
  end
end
if node['Win2019STIG']['stigrule_103363']['Manage']
  dsc_resource 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available_103363' do
    resource :SecurityOption
    property :name, 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
    property :Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available, node['Win2019STIG']['stigrule_103363']['Setting']['Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available']
  end
end
if node['Win2019STIG']['stigrule_103365']['Manage']
  registry_key 'LsaCfgFlags_103365' do
    key node['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_Key']
    values [{
      name: 'LsaCfgFlags',
      type: node['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_ValueType'],
      data: node['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103365']['Setting']['LsaCfgFlags_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103367']['Manage']
  dsc_resource 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_103367' do
    resource :SecurityOption
    property :name, 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
    property :Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only, node['Win2019STIG']['stigrule_103367']['Setting']['Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only']
  end
end
if node['Win2019STIG']['stigrule_103369']['Manage']
  dsc_resource 'Accounts_Rename_administrator_account_103369' do
    resource :SecurityOption
    property :name, 'Accounts_Rename_administrator_account'
    property :Accounts_Rename_administrator_account, node['Win2019STIG']['stigrule_103369']['Setting']['Accounts_Rename_administrator_account']
  end
end
if node['Win2019STIG']['stigrule_103371']['Manage']
  dsc_resource 'Accounts_Rename_guest_account_103371' do
    resource :SecurityOption
    property :name, 'Accounts_Rename_guest_account'
    property :Accounts_Rename_guest_account, node['Win2019STIG']['stigrule_103371']['Setting']['Accounts_Rename_guest_account']
  end
end
if node['Win2019STIG']['stigrule_103373']['Manage']
  dsc_resource 'Domain_member_Maximum_machine_account_password_age_103373' do
    resource :SecurityOption
    property :name, 'Domain_member_Maximum_machine_account_password_age'
    property :Domain_member_Maximum_machine_account_password_age, node['Win2019STIG']['stigrule_103373']['Setting']['Domain_member_Maximum_machine_account_password_age']
  end
end
if node['Win2019STIG']['stigrule_103375']['Manage']
  dsc_resource 'Interactive_logon_Smart_card_removal_behavior_103375' do
    resource :SecurityOption
    property :name, 'Interactive_logon_Smart_card_removal_behavior'
    property :Interactive_logon_Smart_card_removal_behavior, node['Win2019STIG']['stigrule_103375']['Setting']['Interactive_logon_Smart_card_removal_behavior']
  end
end
if node['Win2019STIG']['stigrule_103377']['Manage']
  dsc_resource 'Network_access_Allow_anonymous_SID_Name_translation_103377' do
    resource :SecurityOption
    property :name, 'Network_access_Allow_anonymous_SID_Name_translation'
    property :Network_access_Allow_anonymous_SID_Name_translation, node['Win2019STIG']['stigrule_103377']['Setting']['Network_access_Allow_anonymous_SID_Name_translation']
  end
end
if node['Win2019STIG']['stigrule_103379']['Manage']
  dsc_resource 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_103379' do
    resource :SecurityOption
    property :name, 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
    property :Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts, node['Win2019STIG']['stigrule_103379']['Setting']['Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts']
  end
end
if node['Win2019STIG']['stigrule_103381']['Manage']
  dsc_resource 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users_103381' do
    resource :SecurityOption
    property :name, 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
    property :Network_access_Let_Everyone_permissions_apply_to_anonymous_users, node['Win2019STIG']['stigrule_103381']['Setting']['Network_access_Let_Everyone_permissions_apply_to_anonymous_users']
  end
end
if node['Win2019STIG']['stigrule_103383']['Manage']
  dsc_resource 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_103383' do
    resource :SecurityOption
    property :name, 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
    property :Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM, node['Win2019STIG']['stigrule_103383']['Setting']['Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM']
  end
end
if node['Win2019STIG']['stigrule_103385']['Manage']
  dsc_resource 'Network_security_Allow_LocalSystem_NULL_session_fallback_103385' do
    resource :SecurityOption
    property :name, 'Network_security_Allow_LocalSystem_NULL_session_fallback'
    property :Network_security_Allow_LocalSystem_NULL_session_fallback, node['Win2019STIG']['stigrule_103385']['Setting']['Network_security_Allow_LocalSystem_NULL_session_fallback']
  end
end
if node['Win2019STIG']['stigrule_103387']['Manage']
  dsc_resource 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_103387' do
    resource :SecurityOption
    property :name, 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
    property :Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities, node['Win2019STIG']['stigrule_103387']['Setting']['Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities']
  end
end
if node['Win2019STIG']['stigrule_103389']['Manage']
  dsc_resource 'Network_security_LAN_Manager_authentication_level_103389' do
    resource :SecurityOption
    property :name, 'Network_security_LAN_Manager_authentication_level'
    property :Network_security_LAN_Manager_authentication_level, node['Win2019STIG']['stigrule_103389']['Setting']['Network_security_LAN_Manager_authentication_level']
  end
end
if node['Win2019STIG']['stigrule_103391']['Manage']
  dsc_resource 'Network_security_LDAP_client_signing_requirements_103391' do
    resource :SecurityOption
    property :name, 'Network_security_LDAP_client_signing_requirements'
    property :Network_security_LDAP_client_signing_requirements, node['Win2019STIG']['stigrule_103391']['Setting']['Network_security_LDAP_client_signing_requirements']
  end
end
if node['Win2019STIG']['stigrule_103393']['Manage']
  dsc_resource 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_103393' do
    resource :SecurityOption
    property :name, 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
    property :Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients, node['Win2019STIG']['stigrule_103393']['Setting']['Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients']
  end
end
if node['Win2019STIG']['stigrule_103395']['Manage']
  dsc_resource 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_103395' do
    resource :SecurityOption
    property :name, 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
    property :Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers, node['Win2019STIG']['stigrule_103395']['Setting']['Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers']
  end
end
if node['Win2019STIG']['stigrule_103397']['Manage']
  dsc_resource 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links_103397' do
    resource :SecurityOption
    property :name, 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
    property :System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links, node['Win2019STIG']['stigrule_103397']['Setting']['System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links']
  end
end
if node['Win2019STIG']['stigrule_103399']['Manage']
  registry_key 'SaveZoneInformation_103399' do
    key node['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_Key']
    values [{
      name: 'SaveZoneInformation',
      type: node['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_ValueType'],
      data: node['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103399']['Setting']['SaveZoneInformation_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103459']['Manage']
  registry_key 'NoAutoplayfornonVolume_103459' do
    key node['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_Key']
    values [{
      name: 'NoAutoplayfornonVolume',
      type: node['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_ValueType'],
      data: node['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103459']['Setting']['NoAutoplayfornonVolume_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103461']['Manage']
  registry_key 'NoAutorun_103461' do
    key node['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_Key']
    values [{
      name: 'NoAutorun',
      type: node['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_ValueType'],
      data: node['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103461']['Setting']['NoAutorun_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103463']['Manage']
  registry_key 'NoDriveTypeAutoRun_103463' do
    key node['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_Key']
    values [{
      name: 'NoDriveTypeAutoRun',
      type: node['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_ValueType'],
      data: node['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103463']['Setting']['NoDriveTypeAutoRun_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103469']['Manage']
  windows_feature_powershell 'Fax_103469' do
    feature_name 'Fax'
    action node['Win2019STIG']['stigrule_103469']['Setting']['Fax_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103471']['Manage']
  windows_feature_powershell 'PNRP_103471' do
    feature_name 'PNRP'
    action node['Win2019STIG']['stigrule_103471']['Setting']['PNRP_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103473']['Manage']
  windows_feature_powershell 'Simple_TCPIP_103473' do
    feature_name 'Simple-TCPIP'
    action node['Win2019STIG']['stigrule_103473']['Setting']['Simple_TCPIP_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103475']['Manage']
  windows_feature_powershell 'TFTP_Client_103475' do
    feature_name 'TFTP-Client'
    action node['Win2019STIG']['stigrule_103475']['Setting']['TFTP_Client_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103477']['Manage']
  windows_feature_powershell 'FS_SMB1_103477' do
    feature_name 'FS-SMB1'
    action node['Win2019STIG']['stigrule_103477']['Setting']['FS_SMB1_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103479']['Manage']
  registry_key 'SMB1_103479' do
    key node['Win2019STIG']['stigrule_103479']['Setting']['SMB1_Key']
    values [{
      name: 'SMB1',
      type: node['Win2019STIG']['stigrule_103479']['Setting']['SMB1_ValueType'],
      data: node['Win2019STIG']['stigrule_103479']['Setting']['SMB1_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103479']['Setting']['SMB1_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103481']['Manage']
  registry_key 'Start_103481' do
    key node['Win2019STIG']['stigrule_103481']['Setting']['Start_Key']
    values [{
      name: 'Start',
      type: node['Win2019STIG']['stigrule_103481']['Setting']['Start_ValueType'],
      data: node['Win2019STIG']['stigrule_103481']['Setting']['Start_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103481']['Setting']['Start_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103483']['Manage']
  windows_feature_powershell 'PowerShell_v2_103483' do
    feature_name 'PowerShell-v2'
    action node['Win2019STIG']['stigrule_103483']['Setting']['PowerShell_v2_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103485']['Manage']
  registry_key 'NoLockScreenSlideshow_103485' do
    key node['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_Key']
    values [{
      name: 'NoLockScreenSlideshow',
      type: node['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_ValueType'],
      data: node['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103485']['Setting']['NoLockScreenSlideshow_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103487']['Manage']
  registry_key 'UseLogonCredential_103487' do
    key node['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_Key']
    values [{
      name: 'UseLogonCredential',
      type: node['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_ValueType'],
      data: node['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103487']['Setting']['UseLogonCredential_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103489']['Manage']
  registry_key 'DisableWebPnPDownload_103489' do
    key node['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_Key']
    values [{
      name: 'DisableWebPnPDownload',
      type: node['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_ValueType'],
      data: node['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103489']['Setting']['DisableWebPnPDownload_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103491']['Manage']
  registry_key 'DisableHTTPPrinting_103491' do
    key node['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_Key']
    values [{
      name: 'DisableHTTPPrinting',
      type: node['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_ValueType'],
      data: node['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103491']['Setting']['DisableHTTPPrinting_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103493']['Manage']
  registry_key 'DontDisplayNetworkSelectionUI_103493' do
    key node['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_Key']
    values [{
      name: 'DontDisplayNetworkSelectionUI',
      type: node['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_ValueType'],
      data: node['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103493']['Setting']['DontDisplayNetworkSelectionUI_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103495']['Manage']
  registry_key 'DisableInventory_103495' do
    key node['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_Key']
    values [{
      name: 'DisableInventory',
      type: node['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_ValueType'],
      data: node['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103495']['Setting']['DisableInventory_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103497']['Manage']
  registry_key 'EnableSmartScreen_103497' do
    key node['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_Key']
    values [{
      name: 'EnableSmartScreen',
      type: node['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_ValueType'],
      data: node['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103497']['Setting']['EnableSmartScreen_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103499']['Manage']
  registry_key 'AllowBasicAuthInClear_103499' do
    key node['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_Key']
    values [{
      name: 'AllowBasicAuthInClear',
      type: node['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_ValueType'],
      data: node['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103499']['Setting']['AllowBasicAuthInClear_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103501']['Manage']
  registry_key 'AllowIndexingEncryptedStoresOrItems_103501' do
    key node['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_Key']
    values [{
      name: 'AllowIndexingEncryptedStoresOrItems',
      type: node['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_ValueType'],
      data: node['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103501']['Setting']['AllowIndexingEncryptedStoresOrItems_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103505']['Manage']
  registry_key 'EnumerateLocalUsers_103505' do
    key node['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_Key']
    values [{
      name: 'EnumerateLocalUsers',
      type: node['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_ValueType'],
      data: node['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103505']['Setting']['EnumerateLocalUsers_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103507']['Manage']
  windows_feature_powershell 'Web_Ftp_Service_103507' do
    feature_name 'Web-Ftp-Service'
    action node['Win2019STIG']['stigrule_103507']['Setting']['Web_Ftp_Service_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103509']['Manage']
  windows_feature_powershell 'Telnet_Client_103509' do
    feature_name 'Telnet-Client'
    action node['Win2019STIG']['stigrule_103509']['Setting']['Telnet_Client_Ensure']
    all true
  end
end
if node['Win2019STIG']['stigrule_103511']['Manage']
  registry_key 'DisablePasswordSaving_103511' do
    key node['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_Key']
    values [{
      name: 'DisablePasswordSaving',
      type: node['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_ValueType'],
      data: node['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103511']['Setting']['DisablePasswordSaving_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103513']['Manage']
  registry_key 'fPromptForPassword_103513' do
    key node['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_Key']
    values [{
      name: 'fPromptForPassword',
      type: node['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_ValueType'],
      data: node['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103513']['Setting']['fPromptForPassword_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103515']['Manage']
  registry_key 'DisableRunAs_103515' do
    key node['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_Key']
    values [{
      name: 'DisableRunAs',
      type: node['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_ValueType'],
      data: node['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103515']['Setting']['DisableRunAs_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103517']['Manage']
  dsc_resource 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account_103517' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
    property :User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account, node['Win2019STIG']['stigrule_103517']['Setting']['User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account']
  end
end
if node['Win2019STIG']['stigrule_103519']['Manage']
  dsc_resource 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_103519' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
    property :User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users, node['Win2019STIG']['stigrule_103519']['Setting']['User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users']
  end
end
if node['Win2019STIG']['stigrule_103521']['Manage']
  dsc_resource 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_103521' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
    property :User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode, node['Win2019STIG']['stigrule_103521']['Setting']['User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode']
  end
end
if node['Win2019STIG']['stigrule_103539']['Manage']
  registry_key 'RestrictRemoteClients_103539' do
    key node['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_Key']
    values [{
      name: 'RestrictRemoteClients',
      type: node['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_ValueType'],
      data: node['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103539']['Setting']['RestrictRemoteClients_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103541']['Manage']
  dsc_resource 'Domain_member_Disable_machine_account_password_changes_103541' do
    resource :SecurityOption
    property :name, 'Domain_member_Disable_machine_account_password_changes'
    property :Domain_member_Disable_machine_account_password_changes, node['Win2019STIG']['stigrule_103541']['Setting']['Domain_member_Disable_machine_account_password_changes']
  end
end
if node['Win2019STIG']['stigrule_103545']['Manage']
  dsc_resource 'Password_must_meet_complexity_requirements_103545' do
    resource :AccountPolicy
    property :name, 'Password_must_meet_complexity_requirements'
    property :Password_must_meet_complexity_requirements, node['Win2019STIG']['stigrule_103545']['Setting']['Password_must_meet_complexity_requirements']
  end
end
if node['Win2019STIG']['stigrule_103549']['Manage']
  dsc_resource 'Minimum_Password_Length_103549' do
    resource :AccountPolicy
    property :name, 'Minimum_Password_Length'
    property :Minimum_Password_Length, node['Win2019STIG']['stigrule_103549']['Setting']['Minimum_Password_Length']
  end
end
if node['Win2019STIG']['stigrule_103551']['Manage']
  dsc_resource 'Store_passwords_using_reversible_encryption_103551' do
    resource :AccountPolicy
    property :name, 'Store_passwords_using_reversible_encryption'
    property :Store_passwords_using_reversible_encryption, node['Win2019STIG']['stigrule_103551']['Setting']['Store_passwords_using_reversible_encryption']
  end
end
if node['Win2019STIG']['stigrule_103553']['Manage']
  dsc_resource 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change_103553' do
    resource :SecurityOption
    property :name, 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
    property :Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change, node['Win2019STIG']['stigrule_103553']['Setting']['Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change']
  end
end
if node['Win2019STIG']['stigrule_103555']['Manage']
  dsc_resource 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers_103555' do
    resource :SecurityOption
    property :name, 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
    property :Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers, node['Win2019STIG']['stigrule_103555']['Setting']['Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers']
  end
end
if node['Win2019STIG']['stigrule_103557']['Manage']
  dsc_resource 'Minimum_Password_Age_103557' do
    resource :AccountPolicy
    property :name, 'Minimum_Password_Age'
    property :Minimum_Password_Age, node['Win2019STIG']['stigrule_103557']['Setting']['Minimum_Password_Age']
  end
end
if node['Win2019STIG']['stigrule_103563']['Manage']
  dsc_resource 'Maximum_Password_Age_103563' do
    resource :AccountPolicy
    property :name, 'Maximum_Password_Age'
    property :Maximum_Password_Age, node['Win2019STIG']['stigrule_103563']['Setting']['Maximum_Password_Age']
  end
end
if node['Win2019STIG']['stigrule_103565']['Manage']
  dsc_resource 'Enforce_password_history_103565' do
    resource :AccountPolicy
    property :name, 'Enforce_password_history'
    property :Enforce_password_history, node['Win2019STIG']['stigrule_103565']['Setting']['Enforce_password_history']
  end
end
if node['Win2019STIG']['stigrule_103573']['Manage']
  windows_certificate '8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_103573' do
    source node['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Path']
    store_name node['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Store']
    user_store node['Win2019STIG']['stigrule_103573']['Setting']['8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561_Location']
  end
end
if node['Win2019STIG']['stigrule_103573']['Manage']
  windows_certificate 'D73CA91102A2204A36459ED32213B467D7CE97FB_103573' do
    source node['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Path']
    store_name node['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Store']
    user_store node['Win2019STIG']['stigrule_103573']['Setting']['D73CA91102A2204A36459ED32213B467D7CE97FB_Location']
  end
end
if node['Win2019STIG']['stigrule_103573']['Manage']
  windows_certificate 'B8269F25DBD937ECAFD4C35A9838571723F2D026_103573' do
    source node['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Path']
    store_name node['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Store']
    user_store node['Win2019STIG']['stigrule_103573']['Setting']['B8269F25DBD937ECAFD4C35A9838571723F2D026_Location']
  end
end
if node['Win2019STIG']['stigrule_103573']['Manage']
  windows_certificate '4ECB5CC3095670454DA1CBD410FC921F46B8564B_103573' do
    source node['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Path']
    store_name node['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Store']
    user_store node['Win2019STIG']['stigrule_103573']['Setting']['4ECB5CC3095670454DA1CBD410FC921F46B8564B_Location']
  end
end
if node['Win2019STIG']['stigrule_103575']['Manage']
  windows_certificate '22BBE981F0694D246CC1472ED2B021DC8540A22F_103575' do
    source node['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Path']
    store_name node['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Store']
    user_store node['Win2019STIG']['stigrule_103575']['Setting']['22BBE981F0694D246CC1472ED2B021DC8540A22F_Location']
  end
end
if node['Win2019STIG']['stigrule_103575']['Manage']
  windows_certificate 'FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_103575' do
    source node['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Path']
    store_name node['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Store']
    user_store node['Win2019STIG']['stigrule_103575']['Setting']['FFAD03329B9E527A43EEC66A56F9CBB5393E6E13_Location']
  end
end
if node['Win2019STIG']['stigrule_103575']['Manage']
  windows_certificate 'FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_103575' do
    source node['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Path']
    store_name node['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Store']
    user_store node['Win2019STIG']['stigrule_103575']['Setting']['FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4_Location']
  end
end
if node['Win2019STIG']['stigrule_103577']['Manage']
  windows_certificate 'DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_103577' do
    source node['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Path']
    store_name node['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Store']
    user_store node['Win2019STIG']['stigrule_103577']['Setting']['DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3_Location']
  end
end
if node['Win2019STIG']['stigrule_103577']['Manage']
  windows_certificate '929BF3196896994C0A201DF4A5B71F603FEFBF2E_103577' do
    source node['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Path']
    store_name node['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Store']
    user_store node['Win2019STIG']['stigrule_103577']['Setting']['929BF3196896994C0A201DF4A5B71F603FEFBF2E_Location']
  end
end
if node['Win2019STIG']['stigrule_103579']['Manage']
  dsc_resource 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer_103579' do
    resource :SecurityOption
    property :name, 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
    property :System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer, node['Win2019STIG']['stigrule_103579']['Setting']['System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer']
  end
end
if node['Win2019STIG']['stigrule_103583']['Manage']
  dsc_resource 'Accounts_Guest_account_status_103583' do
    resource :SecurityOption
    property :name, 'Accounts_Guest_account_status'
    property :Accounts_Guest_account_status, node['Win2019STIG']['stigrule_103583']['Setting']['Accounts_Guest_account_status']
  end
end
if node['Win2019STIG']['stigrule_103585']['Manage']
  registry_key 'AllowUnencryptedTraffic_103585' do
    key node['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_Key']
    values [{
      name: 'AllowUnencryptedTraffic',
      type: node['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_ValueType'],
      data: node['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103585']['Setting']['AllowUnencryptedTraffic_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103587']['Manage']
  registry_key 'AllowUnencryptedTraffic_103587' do
    key node['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_Key']
    values [{
      name: 'AllowUnencryptedTraffic',
      type: node['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_ValueType'],
      data: node['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103587']['Setting']['AllowUnencryptedTraffic_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103589']['Manage']
  registry_key 'AllowBasic_103589' do
    key node['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_Key']
    values [{
      name: 'AllowBasic',
      type: node['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_ValueType'],
      data: node['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103589']['Setting']['AllowBasic_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103593']['Manage']
  registry_key 'AllowBasic_103593' do
    key node['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_Key']
    values [{
      name: 'AllowBasic',
      type: node['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_ValueType'],
      data: node['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103593']['Setting']['AllowBasic_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103591']['Manage']
  registry_key 'AllowDigest_103591' do
    key node['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_Key']
    values [{
      name: 'AllowDigest',
      type: node['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_ValueType'],
      data: node['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103591']['Setting']['AllowDigest_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103597']['Manage']
  dsc_resource 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing_103597' do
    resource :SecurityOption
    property :name, 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
    property :System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing, node['Win2019STIG']['stigrule_103597']['Setting']['System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing']
  end
end
if node['Win2019STIG']['stigrule_103603']['Manage']
  registry_key 'EnumerateAdministrators_103603' do
    key node['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_Key']
    values [{
      name: 'EnumerateAdministrators',
      type: node['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_ValueType'],
      data: node['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103603']['Setting']['EnumerateAdministrators_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103605']['Manage']
  registry_key 'LocalAccountTokenFilterPolicy_103605' do
    key node['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_Key']
    values [{
      name: 'LocalAccountTokenFilterPolicy',
      type: node['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_ValueType'],
      data: node['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103605']['Setting']['LocalAccountTokenFilterPolicy_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103607']['Manage']
  dsc_resource 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_103607' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
    property :User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop, node['Win2019STIG']['stigrule_103607']['Setting']['User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop']
  end
end
if node['Win2019STIG']['stigrule_103609']['Manage']
  dsc_resource 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_103609' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
    property :User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode, node['Win2019STIG']['stigrule_103609']['Setting']['User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode']
  end
end
if node['Win2019STIG']['stigrule_103611']['Manage']
  dsc_resource 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation_103611' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
    property :User_Account_Control_Detect_application_installations_and_prompt_for_elevation, node['Win2019STIG']['stigrule_103611']['Setting']['User_Account_Control_Detect_application_installations_and_prompt_for_elevation']
  end
end
if node['Win2019STIG']['stigrule_103613']['Manage']
  dsc_resource 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_103613' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
    property :User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations, node['Win2019STIG']['stigrule_103613']['Setting']['User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations']
  end
end
if node['Win2019STIG']['stigrule_103615']['Manage']
  dsc_resource 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations_103615' do
    resource :SecurityOption
    property :name, 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
    property :User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations, node['Win2019STIG']['stigrule_103615']['Setting']['User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations']
  end
end
if node['Win2019STIG']['stigrule_103619']['Manage']
  registry_key 'fDisableCdm_103619' do
    key node['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_Key']
    values [{
      name: 'fDisableCdm',
      type: node['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_ValueType'],
      data: node['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103619']['Setting']['fDisableCdm_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103623']['Manage']
  dsc_resource 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_103623' do
    resource :SecurityOption
    property :name, 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
    property :Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares, node['Win2019STIG']['stigrule_103623']['Setting']['Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares']
  end
end
if node['Win2019STIG']['stigrule_103625']['Manage']
  dsc_resource 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares_103625' do
    resource :SecurityOption
    property :name, 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
    property :Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares, node['Win2019STIG']['stigrule_103625']['Setting']['Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares']
  end
end
if node['Win2019STIG']['stigrule_103627']['Manage']
  registry_key 'NoNameReleaseOnDemand_103627' do
    key node['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_Key']
    values [{
      name: 'NoNameReleaseOnDemand',
      type: node['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_ValueType'],
      data: node['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103627']['Setting']['NoNameReleaseOnDemand_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['stigrule_103631']['Manage']
  dsc_resource 'Domain_controller_LDAP_server_signing_requirements_103631' do
    resource :SecurityOption
    property :name, 'Domain_controller_LDAP_server_signing_requirements'
    property :Domain_controller_LDAP_server_signing_requirements, node['Win2019STIG']['stigrule_103631']['Setting']['Domain_controller_LDAP_server_signing_requirements']
  end
end
if node['Win2019STIG']['stigrule_103633']['Manage']
  dsc_resource 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_103633' do
    resource :SecurityOption
    property :name, 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
    property :Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always, node['Win2019STIG']['stigrule_103633']['Setting']['Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always']
  end
end
if node['Win2019STIG']['stigrule_103635']['Manage']
  dsc_resource 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible_103635' do
    resource :SecurityOption
    property :name, 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
    property :Domain_member_Digitally_encrypt_secure_channel_data_when_possible, node['Win2019STIG']['stigrule_103635']['Setting']['Domain_member_Digitally_encrypt_secure_channel_data_when_possible']
  end
end
if node['Win2019STIG']['stigrule_103637']['Manage']
  dsc_resource 'Domain_member_Digitally_sign_secure_channel_data_when_possible_103637' do
    resource :SecurityOption
    property :name, 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
    property :Domain_member_Digitally_sign_secure_channel_data_when_possible, node['Win2019STIG']['stigrule_103637']['Setting']['Domain_member_Digitally_sign_secure_channel_data_when_possible']
  end
end
if node['Win2019STIG']['stigrule_103639']['Manage']
  dsc_resource 'Domain_member_Require_strong_Windows_2000_or_later_session_key_103639' do
    resource :SecurityOption
    property :name, 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
    property :Domain_member_Require_strong_Windows_2000_or_later_session_key, node['Win2019STIG']['stigrule_103639']['Setting']['Domain_member_Require_strong_Windows_2000_or_later_session_key']
  end
end
if node['Win2019STIG']['stigrule_103641']['Manage']
  dsc_resource 'Microsoft_network_client_Digitally_sign_communications_always_103641' do
    resource :SecurityOption
    property :name, 'Microsoft_network_client_Digitally_sign_communications_always'
    property :Microsoft_network_client_Digitally_sign_communications_always, node['Win2019STIG']['stigrule_103641']['Setting']['Microsoft_network_client_Digitally_sign_communications_always']
  end
end
if node['Win2019STIG']['stigrule_103643']['Manage']
  dsc_resource 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees_103643' do
    resource :SecurityOption
    property :name, 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
    property :Microsoft_network_client_Digitally_sign_communications_if_server_agrees, node['Win2019STIG']['stigrule_103643']['Setting']['Microsoft_network_client_Digitally_sign_communications_if_server_agrees']
  end
end
if node['Win2019STIG']['stigrule_103645']['Manage']
  dsc_resource 'Microsoft_network_server_Digitally_sign_communications_always_103645' do
    resource :SecurityOption
    property :name, 'Microsoft_network_server_Digitally_sign_communications_always'
    property :Microsoft_network_server_Digitally_sign_communications_always, node['Win2019STIG']['stigrule_103645']['Setting']['Microsoft_network_server_Digitally_sign_communications_always']
  end
end
if node['Win2019STIG']['stigrule_103647']['Manage']
  dsc_resource 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees_103647' do
    resource :SecurityOption
    property :name, 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
    property :Microsoft_network_server_Digitally_sign_communications_if_client_agrees, node['Win2019STIG']['stigrule_103647']['Setting']['Microsoft_network_server_Digitally_sign_communications_if_client_agrees']
  end
end
if node['Win2019STIG']['stigrule_103649']['Manage']
  registry_key 'NoDataExecutionPrevention_103649' do
    key node['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_Key']
    values [{
      name: 'NoDataExecutionPrevention',
      type: node['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_ValueType'],
      data: node['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_ValueData']
    }]
    action node['Win2019STIG']['stigrule_103649']['Setting']['NoDataExecutionPrevention_Ensure']
    recursive true
  end
end
if node['Win2019STIG']['XCCDF_result']['Manage']
  cookbook_file "#{Chef::Config[:file_cache_path]}/stig_xml.rb" do
    source 'stig_xml.rb'
  end
  cookbook_file "#{Chef::Config[:file_cache_path]}/U_MS_Windows_Server_2019_STIG_V1R3_Manual-xccdf.xml" do
    source 'U_MS_Windows_Server_2019_STIG_V1R3_Manual-xccdf.xml'
  end
  chef_handler 'Chef::Handler::StigXml' do
    source "#{Chef::Config[:file_cache_path]}/stig_xml.rb"
    arguments :stigName => 'U_MS_Windows_Server_2019_STIG_V1R3_Manual-xccdf.xml'
  end
end
