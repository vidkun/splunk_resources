#!/user/bin/env ruby
=begin
#
# Date: 20140722
# Author: Ryan (vidkun)
#
# Script to connect to a Nexpose Security Console and import results into Splunk Enterprise using the following event format:
# last_scan=#{a.last_scan} dest=#{a.ip} dest_nt_host=#{a.name} mac=#{a.mac} os=#{a.os} severity=#{v.severity} signature_id=#{v.id} signature=#{v.title} cve=#{cve_nums} bugtraq=#{bugtraq_ids}
#
# USAGE:
# 1) Edit script to assign which sites you want to import
# 2) Configure Splunk to run the script as a scripted input
#
=end
require 'nexpose'
require 'csv'
include Nexpose

time = Time.new
NOW = time.localtime
site_list = [ 1, 2, 3, 4 ]
begin
# Check if script is running in unattended mode and prompt for creds if not
	if ARGV[0] == '-u'		# Use hard coded credentials for unattended mode
		#nsc_console = '<insert security console>'
		#nsc_user = '<insert username>'
		#nsc_pass = '<insert password>'
	else		# Prompt for and get user credentials for connection to Nexpose Security Console
		print "Enter Nexpose User Name: "
		nsc_user = gets.chomp
		print "Enter Nexpose User Password: "
		nsc_pass = gets.chomp
		print "Enter Target Nexpose Security Console: "
		nsc_console = gets.chomp
	end
# Creates a new connection object. Requires ('host', 'user', 'pass')
nsc = Connection.new(nsc_console, nsc_user, nsc_pass)


nsc.login
rescue Exception => e
	puts e.message
end

	query = "WITH vuln_tags AS (SELECT vulnerability_id, array_to_string(array_agg(category_name ORDER BY category_name ASC), ',') AS tags FROM dim_vulnerability_category GROUP BY vulnerability_id), vulnerability_cves AS (SELECT vulnerability_id, array_to_string(array_agg(reference), ',') AS cves FROM dim_vulnerability_reference WHERE source = 'CVE' GROUP BY vulnerability_id), vulnerability_bugs AS (SELECT vulnerability_id, array_to_string(array_agg(reference), ',') AS bugs FROM dim_vulnerability_reference WHERE source = 'BID' GROUP BY vulnerability_id), vuln_skill AS (SELECT vulnerability_id, array_to_string(array_agg(skill_level), ',') AS skill FROM dim_vulnerability_exploit GROUP BY vulnerability_id) SELECT fa.scan_started AS start_time, fa.scan_finished AS end_time, da.ip_address AS dest_ip, da.host_name AS dest_nt_host, da.mac_address AS dest_mac, dos.description AS os, dv.nexpose_id AS signature_id, dv.title AS signature, dv.severity AS severity, dv.exploits AS exploits, dv.malware_kits AS malware_kits, dve.skill AS skill_mv, round(dv.cvss_score::numeric, 2) AS cvss_score, cvss_vector, vtags.tags AS category_mv, vcves.cves AS cve_mv, vbugs.bugs AS bugtraq_mv FROM fact_asset_vulnerability_finding favf JOIN dim_asset da USING (asset_id) JOIN fact_asset fa USING (asset_id) JOIN dim_operating_system dos USING (operating_system_id) JOIN dim_vulnerability dv USING (vulnerability_id) JOIN vuln_tags vtags USING (vulnerability_id) LEFT OUTER JOIN vulnerability_cves vcves USING (vulnerability_id) LEFT OUTER JOIN vulnerability_bugs vbugs USING (vulnerability_id) JOIN vuln_skill dve USING (vulnerability_id) JOIN dim_site_asset dsa USING (asset_id) JOIN dim_site ds USING (site_id) WHERE ds.site_id IN (#{site_list.join(', ')}) ORDER BY da.ip_address ASC, dv.title ASC"
	report_config = Nexpose::AdhocReportConfig.new(nil, 'sql')
	report_config.add_filter('version', '1.2.1')
	report_config.add_filter('query', query)
	report_output = report_config.generate(nsc, timeout = 7200)
	csv_output = CSV.parse(report_output.chomp, { :headers => true, :return_headers => true, :header_converters => :symbol, :converters => :all })
	#Strip first row of CSV (headers)
	csv_output.delete(0)
	csv_output.each do |r|
	if r[:skill_mv].to_s.include?(",")
	  skill_split = r[:skill_mv].split(',').join(', ')
	else
	  skill_split = r[:skill_mv]
	end

	if r[:category_mv].to_s.include?(",")
	  category_split = r[:category_mv].split(',').join(', ')
	else
	  category_split = r[:category_mv]
	end

	if r[:cve_mv].to_s.include?(",")
	  cve_split = r[:cve_mv].split(',').join(', ')
	else 
	  cve_split = r[:cve_mv]
	end

	if r[:bugtraq_mv].to_s.include?(",")
	  bugs_split = r[:bugtraq_mv].split(',').join(', ')
	else
	  bugs_split = r[:bugtraq_mv]
	end

	# CVE, Bugtraq, Skill and Category all need to come in as *_mv for transforms to properly breakout the multiple values and display with correct name in Splunk	
	splunk_event = "#{NOW} start_time=\"#{r[:start_time]}\" end_time=\"#{r[:end_time]}\" dest_ip=\"#{r[:dest_ip]}\" dest_nt_host=\"#{r[:dest_nt_host]}\" dest_mac=\"#{r[:dest_mac]}\" os=\"#{r[:os]}\" signature_id=\"#{r[:signature_id]}\" signature=\"#{r[:signature]}\" severity=\"#{r[:severity]}\" exploits=\"#{r[:exploits]}\" malware_kits=\"#{r[:malware_kits]}\" skill_mv=\"#{skill_split}\" cvss_score=\"#{r[:cvss_score]}\" cvss_vector=\"#{r[:cvss_vector]}\" category_mv=\"#{category_split}\" cve_mv=\"#{cve_split}\" bugtraq_mv=\"#{bugs_split}\"\n"
	print splunk_event  
	end

nsc.logout

