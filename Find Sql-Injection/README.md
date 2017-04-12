# Find Sql-injection
This script find sql-injection and purpose in json formatted weblog(access.log).
<br>This script does not support the usual access.log. You can modify the script.
<br>Detection rules(regex) are based on SQLMAP

## Usage>

```
Usage: ruby find_sqli_purpose.rb logfile
```

## Example>
```
[root@localhost find_sqli_purpose]# ruby find_sqli_purpose.rb web_access_json.log

[Checking for attack is possible] - /wordpress/wp-admin/?season=1&league_id=1&match_day=1&team_id=1
[Checking for attack is possible] - /wordpress/wp-login.php?redirect_to=http://172.20.3.237/wordpress/wp-admin/?season=1&league_id=1&match_day=1&team_id=1&reauth=1
[Check Firewall] - 7369 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1-- ; EXEC xp_cmdshell('cat ../../../etc/passwd')#
[Check Firewall] - 7369 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#&reauth=1
[Checking for attack is possible] - /wordpress/wp-admin/?season=1&league_id=1&match_day=1&team_id=1
[Checking for attack is possible] - /wordpress/wp-login.php?redirect_to=http://172.20.3.237/wordpress/wp-admin/?season=1&league_id=1&match_day=1&team_id=1&reauth=1
[Checking for attack is possible] - 1'.)'.()()"&match_day=1&team_id=1
[Checking for attack is possible] - 1'.)'.()()"&match_day=1&team_id=1&reauth=1
[Get Parameter Injectable] - 1'JnPkgm<'">OfQMmc&match_day=1&team_id=1
[Get Parameter Injectable] - 1'JnPkgm<'">OfQMmc&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Boolean based] - 1) AND 4961=3130-- pQvy&match_day=1&team_id=1
[Find Vulnerabilities by Boolean based] - 1) AND 4961=3130-- pQvy&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Boolean based] - 1) AND 9655=9655-- ePYE&match_day=1&team_id=1
[Find Vulnerabilities by Boolean based] - 1) AND 9655=9655-- ePYE&match_day=1&team_id=1&reauth=1
...
[Find Vulnerabilities by Error based] - 1) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610)))-- mnmM&match_day=1&team_id=1
[Find Vulnerabilities by Error based] - 1) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610)))-- mnmM&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Error based] - 1) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND (6492=6492&match_day=1&team_id=1
[Find Vulnerabilities by Error based] - 1) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND (6492=6492&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Error based] - 1)) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND ((8738=8738&match_day=1&team_id=1
[Find Vulnerabilities by Error based] - 1)) AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(2044=2044,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND ((8738=8738&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Error based] - 1")) OR (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(8045=8045,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND (("yMcw"="yMcw&match_day=1&team_id=1
[Find Vulnerabilities by Error based] - 1")) OR (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a6b7171,(SELECT (ELT(8045=8045,1))),0x7178787671,0x78))s), 8446744073709551610, 8446744073709551610))) AND (("yMcw"="yMcw&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Error based] - 1)) AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x716a6b7171,(SELECT (ELT(4337=4337,1))),0x7178787671)) USING utf8))) AND ((9566=9566&match_day=1&team_id=1
[Find Vulnerabilities by Error based] - 1)) AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x716a6b7171,(SELECT (ELT(4337=4337,1))),0x7178787671)) USING utf8))) AND ((9566=9566&match_day=1&team_id=1&reauth=1
...
[Find Vulnerabilities by Time based] - 1';(SELECT * FROM (SELECT(SLEEP(5)))ThPK)-- WYsA&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Time based] - 1';SELECT BENCHMARK(5000000,MD5(0x5761574c))#&match_day=1&team_id=1
[Find Vulnerabilities by Time based] - 1';SELECT BENCHMARK(5000000,MD5(0x5761574c))#&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Time based] - 1';SELECT BENCHMARK(5000000,MD5(0x6c675244))-- gaFD&match_day=1&team_id=1
[Find Vulnerabilities by Time based] - 1';SELECT BENCHMARK(5000000,MD5(0x6c675244))-- gaFD&match_day=1&team_id=1&reauth=1
[Find Vulnerabilities by Time based] - 1' AND SLEEP(5)-- NqcP&match_day=1&team_id=1
...
[Find Vulnerable Column Count by Union based] - 1' ORDER BY 1-- HxDn&match_day=1&team_id=1
[Find Vulnerable Column Count by Union based] - 1' ORDER BY 1-- HxDn&match_day=1&team_id=1&reauth=1
[Find Vulnerable Column Count by Union based] - 1' ORDER BY 9989-- BFAf&match_day=1&team_id=1
[Find Vulnerable Column Count by Union based] - 1' ORDER BY 9989-- BFAf&match_day=1&team_id=1&reauth=1
[Find Vulnerable Column Count by Union based] - 1' UNION ALL SELECT NULL-- IowV&match_day=1&team_id=1
[Find Vulnerable Column Count by Union based] - 1' UNION ALL SELECT NULL-- IowV&match_day=1&team_id=1&reauth=1
[Find Vulnerable Column Count by Union based] - 1' UNION ALL SELECT NULL,NULL-- XcDp&match_day=1&team_id=1
[Find Vulnerable Column Count by Union based] - 1' UNION ALL SELECT NULL,NULL-- XcDp&match_day=1&team_id=1&reauth=1
[Find Vulnerable Column Count by Union based] - 1' UNION ALL SELECT NULL,NULL,NULL-- DOEa&match_day=1&team_id=1
...

```

## Dependency
**ruby**
<br>My ruby version is **ruby 2.4.0p0**
