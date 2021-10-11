require 'inspec/resources/registry_key'

class W32timeConfig < Inspec.resource(1)
  name 'w32time_config'
  supports platform: 'windows'
  desc 'Tests Win32Time configuration on Windows'
  example <<~EXAMPLE
      describe win32time_config do
        its("type") { should cmp "NT5DS" }
      end
    EXAMPLE

  def initialize
    @path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
  end

  def ntpserver
    inspec.registry_key(@path).NtpServer.split
  end

  def type
    inspec.registry_key(@path).type
  end

  def to_s
    'w32time_config'
  end
end
