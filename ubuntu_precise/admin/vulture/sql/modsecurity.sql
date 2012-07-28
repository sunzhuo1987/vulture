INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: DetectionOnly','SecRuleEngine DetectionOnly');
INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: Detect and Block','SecRuleEngine On');

INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: ANOMALY SCORING MODE OF OPERATION','

SecDefaultAction "phase:2,pass,nolog,auditlog"

# -=[ Anomaly Scoring Block Mode ]=- INBOUND ANOMALY SCORING
SecAction "phase:1,id:''981206'',t:none,nolog,pass,setvar:tx.anomaly_score_blocking=on"

# Alert and Block based on Anomaly Score and OSVDB Check
SecRule TX:ANOMALY_SCORE "@gt 0" \
    "chain,phase:2,id:''981175'',t:none,deny,log,msg:''Inbound Attack Targeting OSVDB Flagged Resource.'',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}"
        SecRule RESOURCE:OSVDB_VULNERABLE "@eq 1" chain
                SecRule TX:ANOMALY_SCORE_BLOCKING "@streq on"

# Alert and Block based on Anomaly Scores
SecRule TX:ANOMALY_SCORE "@gt 0" \
    "chain,phase:2,id:''981176'',t:none,deny,log,msg:''Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}'',logdata:''Last Matched Data: %{matched_var}'',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}"
        SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_level}" chain
                SecRule TX:ANOMALY_SCORE_BLOCKING "@streq on" chain
                        SecRule TX:/^\d/ "(.*)"

# Alert and Block on a specific attack category such as SQL Injection
#SecRule TX:SQL_INJECTION_SCORE "@gt 0" \
#    "phase:2,t:none,log,block,msg:''SQL Injection Detected (score %{TX.SQL_INJECTION_SCORE}): %{tx.msg}''"


# -=[ Anomaly Scoring Block Mode ]=- OUTBOUND ANOMALY SCORING
#
# Alert and Block on High Anomaly Scores - this would block outbound data leakages
SecRule TX:OUTBOUND_ANOMALY_SCORE "@ge %{tx.outbound_anomaly_score_level}" \
    "chain,phase:4,id:''981200'',t:none,deny,msg:''Outbound Anomaly Score Exceeded (score %{TX.OUTBOUND_ANOMALY_SCORE}): Last Matched Message: %{tx.msg}'',logdata:''Last Matched Data: %{matched_var}''"
        SecRule TX:ANOMALY_SCORE_BLOCKING "@streq on" chain
                SecRule TX:/^\d/ "(.*)"

# -=[ Anomaly Scoring Severity Levels ]=-
SecAction "phase:1,id:''981207'',t:none,nolog,pass, \
setvar:tx.critical_anomaly_score=5, \
setvar:tx.error_anomaly_score=4, \
setvar:tx.warning_anomaly_score=3, \
setvar:tx.notice_anomaly_score=2"

# -=[ Anomaly Scoring Threshold Levels ]=-
SecAction "phase:1,id:''981208'',t:none,nolog,pass,setvar:tx.inbound_anomaly_score_level=5"
SecAction "phase:1,id:''981209'',t:none,nolog,pass,setvar:tx.outbound_anomaly_score_level=4"
');
INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: TRADITIONAL MODE OF OPERATION','SecDefaultAction "phase:2,deny,nolog,auditlog"');
INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: PARANOID MODE','SecAction "phase:1,id:''981210'',t:none,nolog,pass,setvar:tx.paranoid_mode=0"');
INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: HTTP SETTINGS','
## Maximum number of arguments in request limited
SecAction "phase:1,id:''981211'',t:none,nolog,pass,setvar:tx.max_num_args=255"

## Limit argument name length
#SecAction "phase:1,t:none,nolog,pass,setvar:tx.arg_name_length=100"

## Limit value name length
#SecAction "phase:1,t:none,nolog,pass,setvar:tx.arg_length=400"

## Limit arguments total length
#SecAction "phase:1,t:none,nolog,pass,setvar:tx.total_arg_length=64000"

## Individual file size is limited
#SecAction "phase:1,t:none,nolog,pass,setvar:tx.max_file_size=1048576"

## Combined file size is limited
#SecAction "phase:1,t:none,nolog,pass,setvar:tx.combined_file_sizes=1048576"

SecAction "phase:1,id:''981212'',t:none,nolog,pass, \
setvar:''tx.allowed_methods=GET HEAD POST OPTIONS'', \
setvar:''tx.allowed_request_content_type=application/x-www-form-urlencoded multipart/form-data text/xml application/xml application/x-amf'', \
setvar:''tx.allowed_http_versions=HTTP/0.9 HTTP/1.0 HTTP/1.1'', \
setvar:''tx.restricted_extensions=.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/'', \
setvar:''tx.restricted_headers=/Proxy-Connection/ /Lock-Token/ /Content-Range/ /Translate/ /via/ /if/''"
');


INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: BRUTE FORCE PROTECTION','

# -=[ Brute Force Protection ]=-
#
# - Protected URLs: resources to protect (e.g. login pages) - set to your login page
# - Burst Time Slice Interval: time interval window to monitor for bursts
# - Request Threshold: request # threshold to trigger a burst
# - Block Period: temporary block timeout
#
SecAction "phase:1,id:''981214'',t:none,nolog,pass, \
setvar:''tx.brute_force_protected_urls=/login.jsp /partner_login.php'', \
setvar:''tx.brute_force_burst_time_slice=60'', \
setvar:''tx.brute_force_counter_threshold=10'', \
setvar:''tx.brute_force_block_timeout=300''"
');

INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: DoS PROTECTION','

# -=[ DoS Protection ]=-
#
# - Burst Time Slice Interval: time interval window to monitor for bursts
# - Request Threshold: request # threshold to trigger a burst
# - Block Period: temporary block timeout
#
SecAction "phase:1,id:''981215'',t:none,nolog,pass, \
setvar:''tx.dos_burst_time_slice=60'', \
setvar:''tx.dos_counter_threshold=100'', \
setvar:''tx.dos_block_timeout=600''"
');

INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: UTF-8 ENABLED SITE','

# -=[ Check UTF enconding ]=-
#
# We only want to apply this check if UTF-8 encoding is actually used by the site, otherwise
# it will result in false positives.
#
SecAction "phase:1,id:''981216'',t:none,nolog,pass,setvar:tx.crs_validate_utf8_encoding=1"
');


INSERT INTO "modsecurity" (name, rules) VALUES ('POLICY: XML Body Parsing','

# -=[ Enable XML Body Parsing ]=-
#
# The rules in this file will trigger the XML parser upon an XML request
#
# Initiate XML Processor in case of xml content-type
#
SecRule REQUEST_HEADERS:Content-Type "text/xml" \
        "chain,phase:1,id:''981053'',t:none,t:lowercase,pass,nolog"
        SecRule REQBODY_PROCESSOR "!@streq XML" "ctl:requestBodyProcessor=XML"
');

