# Check sql-injection purpose
# @author: Scott
# @version: 1.0

require 'json'
require 'uri'

def checkAttackPurpose(req_line)

  rule = {
    "Get local file data"=>/(select.*(load_file\s*?\())/i,
    "Write file to local system"=>/(select.*(into(\s*?|(\/\*).*(\*\/)|%..|0x..)outfile\s*?))/i,
    "Check Firewall"=>/(UNION.ALL.SELECT.*\'<script>alert\("XSS"\)<\/script>\'.*;.EXEC\sxp_cmdshell.*\(*\/etc\/passwd\'\)\#)/i,
    "Get Parameter Injectable"=>/([a-zA-Z]+<'\">[a-zA-Z]+)/i,
    "Check DBMS"=>/(QUARTER\(.*IS.*NULL|SESSION_USER\(.*LIKE.*USER\(|VERSION\(.*LIKE|ISNULL\(TIMESTAMPADD\(MINUTE\,\d+\,NULL)/i,
    "Verify Target URL"=>/(?!.*\w)(\,|\.)/i,


###########################
###  union based        ###
###########################
		"Check Vulnerable Column Count by Union based"=>/(ORDER.BY.\d+(\-\-|\#))|(?!.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\d+).*(\-\-|\#))/i,
		"Check DBMS Version Infomation by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(VERSION\(|@@VERSION)/i,
    "Check Hostname by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(@@HOSTNAME)/i,
    "Check Database Super_priv by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(super_priv.*FROM.*mysql.user)/i,
    "Check Privileges Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
    "Check Privileges Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
    "Check User Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
    "Check User Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
    "Check Database Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(schema_name)).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
    "Check Database Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(schema_name).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
    "Check Current User by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CURRENT_USER\()/i,
    "Check Current Database by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(DATABASE\()/i,
    "Check Table Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(table_name|\*)).*FROM.*INFORMATION_SCHEMA.TABLES/i,
    "Check Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(table_name|\*).*FROM.*INFORMATION_SCHEMA.TABLES/i,
    "Check Column Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(column_name|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
    "Check Column Name or Type by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(column_name|column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
    "Check Data Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CAST.*(COUNT.*(\*|\w+)).*FROM.*\w+\.\w+)/i,
    "Check Data by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.*(CAST.*(\w+).*FROM.*\w+\.\w+))/i,
    "Brute Force Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.\d+.FROM.*\w+)/i,
    "Brute Force Column Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.\w+.FROM.*\w+)/i,
    "Check Readable Column Location by Union based"=>/(?=.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\w+).*(\-\-|\#))/i,

###########################
###  error based        ###
###########################
    "Check Vulnerabilities by Error based"=>/(0x\w+.*((SELECT.*(ELT.*(\d+\=\d+)))|(SELECT.*(CASE.*WHEN.*(\d+\=(\s|\d+))))).*0x\w+)/i,
		"String Repeat Check by Error based"=>/(0x\w+.*(SELECT.*REPEAT.*0x\w+))/i,
    "Check DBMS Version Infomation by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*(VERSION\(|@@VERSION)).*0x\w+)/i,
    "Check Hostname by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*(@@HOSTNAME)).*0x\w+)/i,
    "Check Database Super_priv by Error based"=>/(0x\w+.*(SELECT.*super_priv.*FROM.*mysql.user).*0x\w+)/i,
    "Check User Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
    "Check User Name by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES).*0x\w+)/i,
    "Check Privileges Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
    "Check Privileges Name by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*(privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES.*0x\w+)/i,
    "Check Database Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
    "Check Database Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
    "Check Current User by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*(CURRENT_USER\()).*0x\w+)/i,
    "Check Current Database by Error based"=>/(0x\w+.*((MID|SUBSTRING|SUBSTR).*(DATABASE\()).*0x\w+)/i,
    "Check Table Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
    "Check Table Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
    "Check Column Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+))/i,
    "Check Column Type by Error based"=>/(0x\w+.*(SELECT.*(MID|SUBSTRING|SUBSTR).*(column_type)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
    "Check Column Name by Error based"=>/(0x\w+.*(SELECT.*(MID|SUBSTRING|SUBSTR).*(column_name)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
    "Check Data Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(\*|\w+).*FROM.*\w+\.\w+).*0x\w+))/i,
    "Check Data by Error based"=>/(0x\w+.*(SELECT.*(MID|SUBSTRING|SUBSTR).*(CAST.*(\w+).*FROM.*\w+\.\w+).*\w+))/i,
    "Brute Force Table Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.*\d+.FROM.*\w+).*0x\w+)/i,
    "Brute Force Column Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.*\w+.FROM.*\w+).*0x\w+)/i,

###########################
###  Time blind based   ###
###########################
    "Check DBMS Version Infomation by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(VERSION\(|@@VERSION\()))/i,
    "Check Hostname by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(@@HOSTNAME)))/i,
    "Check Database Super_priv by Time based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
    "Check User Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
    "Check User Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
    "Check Privileges Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
    "Check Privileges Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
    "Check Database Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
    "Check Database Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
    "Check Current User by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(CURRENT_USER\()))/i,
    "Check Current Database by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(DATABASE\()))/i,
    "Check Table Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
    "Check Table Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
    "Check Column Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
    "Check Column Type by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
    "Check Column Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
		"Check Data Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
		"Check Data by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
    "Brute Force Table Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.*\d+.FROM.*\w+))/i,
    "Brute Force Column Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.*\w+.FROM.*\w+))/i,
    "Check Vulnerabilities by Time based"=>/(SLEEP\(\d|BENCHMARK\(\d)/i,

###############################
###  Boolean blind based    ###
###############################
		"Check Vulnerabilities by Boolean based"=>/(\d+.(\=|\s|\>)\d+)|(\d+\=.*\d+)/i,
		"Check DBMS Version Infomation by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(VERSION\(|@@VERSION)))/i,
		"Check Hostname by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(@@HOSTNAME)))/i,
		"Check Database Super_priv by Boolean based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
		"Check User Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
		"Check User Name by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
		"Check Privileges Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
		"Check Privileges Name by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
		"Check Database Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
		"Check Database Name by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
		"Check Current User by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(CURRENT_USER\()))/i,
		"Check Current Database by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(DATABASE\()))/i,
		"Check Table Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
		"Check Table Name by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
		"Check Column Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
		"Check Column Type by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
		"Check Column Name by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
		"Check Data Count by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
    "Check Data by Boolean based"=>/((ORD|ASCII).*((MID|SUBSTRING|SUBSTR).*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
		"Brute Force Table Name by Boolean based"=>/(EXISTS.(SELECT.*\d+.FROM.*\w+))/i,
		"Brute Force Column Name by Boolean based"=>/(EXISTS.(SELECT.*\w+.FROM.*\w+))/i,

	}

  rule.each do |purpose, pattern|
    res = req_line.match pattern
    if res
      puts "[#{purpose}] - #{req_line}"
      return 0
    end
  end
  puts "[Checking for attack is possible] - #{req_line}"
end

# extract sql-injection Parameter.
# you can use URI.parser :)
pattern1 = /((?=\/\w).*(?<=(\?|&))[\w]+=).*?(?=(union|select|'\s*?|"\s*?|\sand\s|\sor\s|concat\(|mid\(|sleep\(|ascii\(|\sorder\sby|benchmark\(|make_set\(|elt\())/i
pattern2 = /(?=&\D+=).*/

file = ARGV[0]
File.readlines(file).each do |line|
  decode_uri = ""

  hash_data =  JSON.parse(line)
  user_req = URI.unescape(hash_data["Request"]).gsub("GET ", "").gsub(/(HTTP\/1.\d)/i, "")
  user_req = user_req.gsub(/(\/\*[\w\d(\`|\~|\!|\@|\#|\$|\%|\^|\&|\*|\(|\)|\-|\_|\=|\+|\[|\{|\]|\}|\\|\:|\;|\'|\"|\<|\>|\,|\.|\?)\s\r\n\v\f]*\*\/)/i, ' ')
  user_req = user_req.gsub(/(\/\*!\d+|\*\/)/, ' ')
  if user_req.include? "http://"
    decode_uri = URI.unescape(user_req)
  else
    decode_uri = user_req
  end

  if decode_uri.match pattern1
    decode_uri = decode_uri.gsub(Regexp.last_match(1), "")
    if decode_uri.match pattern2
      decode_uri.gsub(pattern2, "")
    end
  end

  checkAttackPurpose(decode_uri)
end
