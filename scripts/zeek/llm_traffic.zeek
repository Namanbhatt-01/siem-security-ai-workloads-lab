##! Zeek IDS script for AI/LLM HTTP telemetry and Threat Analysis
@load base/protocols/http
@load base/frameworks/logging

module LLMTelemetry;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        orig_h: addr &log;
        orig_p: port &log;
        resp_h: addr &log;
        resp_p: port &log;
        method: string &log;
        uri: string &log;
        host: string &log &optional;
        status_code: count &log &optional;
        request_body_len: count &log &default=0;
        response_body_len: count &log &default=0;
        threat_detected: bool &log &default=F;
        threat_type: string &log &default="NONE";
    };
}

event zeek_init() {
    Log::create_stream(LLMTelemetry::LOG, [$columns=Info, $path="llm_inference"]);
}

event http_request(c: connection, method: string, original_URI: string,
                  unescaped_URI: string, version: string) {
    local rec: Info;
    rec$ts = network_time();
    rec$uid = c$uid;
    rec$orig_h = c$id$orig_h;
    rec$orig_p = c$id$orig_p;
    rec$resp_h = c$id$resp_h;
    rec$resp_p = c$id$resp_p;
    rec$method = method;
    rec$uri = original_URI;
    
    if ( c$http?$host )
        rec$host = c$http$host;
        
    if ( /dump/ in original_URI && (c$id$resp_p == 6333/tcp || c$id$resp_p == 8000/tcp) ) {
        rec$threat_detected = T;
        rec$threat_type = "VECTOR_DB_EXFILTRATION";
    }

    Log::write(LLMTelemetry::LOG, rec);
}
