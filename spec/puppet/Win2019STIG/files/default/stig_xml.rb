require 'chef/handler'
require "rexml/document"
require 'tmpdir'
require 'socket'
include REXML

class Chef
  class Handler
    class StigXml < ::Chef::Handler
      attr_reader :config
      def initialize(config={})
        @config = config
        @config[:path] ||= File.join(Dir.tmpdir(), 'xccdf-results.xml')
      end

      def get_id(resource)
        if matches = resource.name.match(%r{_(?<id>\d+)})
          return matches[:id]
        end
      end
      
      def get_rev(id)
        stig = File.read("#{Chef::Config[:file_cache_path]}/#{config[:stigName]}")
        if matches = stig.match(%r{SV-#{id}r(?<rev>\d)_rule})
          return matches[:rev]
        end
      end
      
      def write_xml(resources, output=$stdout)
        document = Document.new
        document <<  XMLDecl.new("1.0", "UTF-8")
        tr = Element.new("cdf:TestResult", tr)
        tr.add_namespace('cdf', 'http://checklists.nist.gov/xccdf/1.2')
        tr.add_attribute("id", "xccdf_mil.disa.stig_testresult_scap_mil.disa.stig_comp_#{config[:stigName]}")
        endtime = Time.now.strftime("%Y-%m-%dT%H:%M:%S")
        tr.add_attribute("end-time", "#{endtime}")
        tg = Element.new("cdf:target", tr)
        tg.text = Socket.gethostname 
        
        rules = {}
        resources.each do |resource|
          id = get_id(resource)
          rev = get_rev(id)
          if id.nil? || rev.nil? then next end
          state = !run_status.updated_resources.include?(resource)
          key = "#{id}r#{rev}"
          if rules[key] != false then
            rules[key] = state
          end
       end
       
        rules.each do |k, v|
          rr = Element.new("cdf:rule-result", tr)
          rr.add_attribute("idref", "xccdf_mil.disa.stig_rule_SV-#{k}_rule")
          result = Element.new("cdf:result", rr)
          result.text = v ? "pass" : "fail"
        end
        sc = Element.new("cdf:score", tr)
        sc.add_attribute("system", "urn:xccdf:scoring:flat-unweighted")
        sc.add_attribute("maximum", "#{rules.size}")
        passing = rules.select{|k, v| v == true}.count
        sc.text = "#{passing}"
        
        document << tr
        formatter = REXML::Formatters::Pretty.new
        formatter.compact = true
        formatter.write(document, output)
      end

      def report
    puts "Writing: #{File.absolute_path(config[:path])}"
        output = File.new config[:path], "w"
        write_xml(run_status.all_resources, output)
      end
    end
  end
end
