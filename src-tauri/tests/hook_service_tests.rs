use anxin_security::services::hook_service::{
    hook_event_to_app_event, hook_event_to_risk_event, parse_hook_pipe_line, FileHookEvent,
    HookPipeMessage, should_retry_hook_pipe_wait,
};

#[test]
fn file_hook_notice_accepts_native_ts_alias() {
    let raw = serde_json::json!({
        "type": "hook_notice",
        "source": "detours_createfile",
        "api": "CreateFileW",
        "pid": 4242,
        "tid": 7,
        "ts": 123456,
        "path": "C:\\Users\\sample\\payload.exe"
    });

    let event: FileHookEvent = serde_json::from_value(raw).expect("native hook event should parse");

    assert_eq!(event.event_type, "hook_notice");
    assert_eq!(event.api.as_deref(), Some("CreateFileW"));
    assert_eq!(event.pid, 4242);
    assert_eq!(event.tid, 7);
    assert_eq!(event.timestamp, 123456);
    assert_eq!(event.path, "C:\\Users\\sample\\payload.exe");
}

#[test]
fn hook_pipe_parser_separates_heartbeat_from_file_event() {
    let heartbeat = parse_hook_pipe_line(r#"{"type":"heartbeat","pid":4242,"ts":10}"#)
        .expect("heartbeat JSON should parse");
    assert!(matches!(heartbeat, Some(HookPipeMessage::Heartbeat)));

    let event = parse_hook_pipe_line(
        r#"{"type":"hook_notice","api":"CreateFileW","pid":4242,"tid":7,"ts":123456,"path":"C:\\Users\\sample\\payload.exe"}"#,
    )
    .expect("hook notice JSON should parse");

    let mut parsed_event = None;
    match event {
        Some(HookPipeMessage::Event(parsed)) => {
            parsed_event = Some(parsed);
        }
        _ => {}
    }
    let parsed = parsed_event.expect("hook notice should parse as file hook event");
    assert_eq!(parsed.event_type, "hook_notice");
    assert_eq!(parsed.api.as_deref(), Some("CreateFileW"));
    assert_eq!(parsed.timestamp, 123456);
}

#[test]
fn hook_event_maps_to_app_event_and_risk_event() {
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_createfile".to_string()),
        api: Some("CreateFileW".to_string()),
        path: "C:\\Users\\sample\\payload.exe".to_string(),
        target_path: None,
        pid: 4242,
        tid: 7,
        process_name: Some("target.exe".to_string()),
        timestamp: 123456,
    };

    let app_event = hook_event_to_app_event(&event);
    assert_eq!(app_event["type"], "file_hook");
    assert_eq!(app_event["provider"], "FileHook");
    assert_eq!(app_event["operation"], "CreateFileW");
    assert_eq!(app_event["processName"], "target.exe");
    assert_eq!(app_event["timestampMs"], 123456);

    let risk_event = hook_event_to_risk_event(&event, &app_event);
    assert_eq!(risk_event.pid, 4242);
    assert_eq!(risk_event.process_name, "target.exe");
    assert_eq!(risk_event.file_path.as_deref(), Some("C:\\Users\\sample\\payload.exe"));
    assert_eq!(risk_event.threat_type, "file_hook_activity");
    assert_eq!(risk_event.rule_id, "FILE_HOOK_ACTIVITY");
    assert!(risk_event.severity >= 26, "hook file activity should enter risk analysis");
}

#[test]
fn hook_pipe_wait_retries_only_transient_wait_states() {
    assert!(should_retry_hook_pipe_wait(232), "ERROR_NO_DATA should wait for more data");
    assert!(
        should_retry_hook_pipe_wait(536),
        "ERROR_PIPE_LISTENING should keep waiting for a client"
    );
    assert!(
        !should_retry_hook_pipe_wait(109),
        "ERROR_BROKEN_PIPE should stop reading the closed pipe"
    );
    assert!(
        !should_retry_hook_pipe_wait(5),
        "ERROR_ACCESS_DENIED should surface as a real pipe error"
    );
}
