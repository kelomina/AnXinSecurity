use anxin_security::services::hook_service::{
    hook_event_to_app_event, hook_event_to_risk_event, parse_hook_pipe_line,
    should_accept_hook_event_from_client, should_retry_hook_pipe_read, should_retry_hook_pipe_wait,
    split_hook_pipe_messages, FileHookEvent, HookPipeMessage, InjectionChainTracker,
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
    assert_eq!(event.target_pid, None);
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
        process_path: None,
        target_pid: None,
        desired_access: None,
        base_address: None,
        start_address: None,
        size: None,
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
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
    assert_eq!(
        risk_event.file_path.as_deref(),
        Some("C:\\Users\\sample\\payload.exe")
    );
    assert_eq!(risk_event.threat_type, "file_hook_activity");
    assert_eq!(risk_event.rule_id, "FILE_HOOK_ACTIVITY");
    assert!(
        risk_event.severity >= 26,
        "hook file activity should enter risk analysis"
    );
}

#[test]
fn process_injection_hook_notice_parses_extended_fields() {
    let raw = serde_json::json!({
        "type": "hook_notice",
        "source": "detours_process_injection",
        "api": "WriteProcessMemory",
        "pid": 5100,
        "tid": 12,
        "ts": 2000,
        "processPath": "C:\\Tools\\file_hook_injector.exe",
        "targetPid": 6200,
        "baseAddress": "0x12340000",
        "size": 520,
        "blocked": false,
        "targetSuspended": true
    });

    let event: FileHookEvent =
        serde_json::from_value(raw).expect("process injection hook event should parse");

    assert_eq!(event.source.as_deref(), Some("detours_process_injection"));
    assert_eq!(event.api.as_deref(), Some("WriteProcessMemory"));
    assert_eq!(event.path, "");
    assert_eq!(
        event.process_path.as_deref(),
        Some("C:\\Tools\\file_hook_injector.exe")
    );
    assert_eq!(event.target_pid, Some(6200));
    assert_eq!(event.base_address.as_deref(), Some("0x12340000"));
    assert_eq!(event.size, Some(520));
    assert_eq!(event.blocked, Some(false));
    assert_eq!(event.target_suspended, Some(true));
}

#[test]
fn injection_chain_tracker_alerts_only_after_remote_thread_chain() {
    let mut tracker = InjectionChainTracker::new(5_000);
    let mut event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("OpenProcess".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("file_hook_injector.exe".to_string()),
        process_path: Some("C:\\Tools\\file_hook_injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: Some(0x2A),
        base_address: None,
        start_address: None,
        size: None,
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    assert!(tracker.record(&event).is_none());

    event.api = Some("VirtualAllocEx".to_string());
    event.timestamp = 1100;
    event.base_address = Some("0x10000000".to_string());
    event.size = Some(1024);
    assert!(tracker.record(&event).is_none());

    event.api = Some("WriteProcessMemory".to_string());
    event.timestamp = 1200;
    assert!(tracker.record(&event).is_none());

    event.api = Some("CreateRemoteThread".to_string());
    event.timestamp = 1300;
    event.start_address = Some("0x7ff900001234".to_string());
    event.blocked = Some(true);
    event.target_suspended = Some(true);
    let alert = tracker
        .record(&event)
        .expect("complete injection chain should alert");

    assert_eq!(alert.source_pid, 5100);
    assert_eq!(alert.target_pid, 6200);
    assert!(alert.apis.iter().any(|api| api == "WriteProcessMemory"));
    assert!(alert.apis.iter().any(|api| api == "CreateRemoteThread"));
    assert_eq!(alert.base_address.as_deref(), Some("0x10000000"));
    assert_eq!(alert.size, Some(1024));
    assert_eq!(alert.start_address.as_deref(), Some("0x7ff900001234"));
    assert!(alert.blocked_by_hook);
    assert!(alert.target_suspended_by_hook);
}

#[test]
fn injection_chain_tracker_does_not_alert_on_open_process_only() {
    let mut tracker = InjectionChainTracker::new(5_000);
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("OpenProcess".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: None,
        process_path: None,
        target_pid: Some(6200),
        desired_access: Some(0x2A),
        base_address: None,
        start_address: None,
        size: None,
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    assert!(tracker.record(&event).is_none());
}

#[test]
fn blocked_remote_thread_notice_can_directly_form_target_alert() {
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("CreateRemoteThread".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("file_hook_injector.exe".to_string()),
        process_path: Some("C:\\Tools\\file_hook_injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: None,
        base_address: Some("0x10000000".to_string()),
        start_address: Some("0x7ff900001234".to_string()),
        size: Some(1024),
        blocked: Some(true),
        target_suspended: Some(true),
        last_error: Some(5),
        chain: Some("OpenProcess>VirtualAllocEx>WriteProcessMemory>CreateRemoteThread".to_string()),
        timestamp: 1300,
    };

    let alert =
        anxin_security::services::hook_service::InjectionChainAlert::from_blocked_hook_event(
            &event,
        )
        .expect("blocked CreateRemoteThread hook notice should directly alert");

    assert_eq!(alert.source_pid, 5100);
    assert_eq!(alert.target_pid, 6200);
    assert!(alert.blocked_by_hook);
    assert!(alert.target_suspended_by_hook);
    assert!(alert.apis.iter().any(|api| api == "CreateRemoteThread"));
}

#[test]
fn blocked_nt_create_thread_ex_notice_can_directly_form_target_alert() {
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("NtCreateThreadEx".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("native_injector.exe".to_string()),
        process_path: Some("C:\\Tools\\native_injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: Some(0x1FFFFF),
        base_address: Some("0x10000000".to_string()),
        start_address: Some("0x7ff900001234".to_string()),
        size: Some(1024),
        blocked: Some(true),
        target_suspended: Some(true),
        last_error: Some(5),
        chain: Some("OpenProcess>VirtualAllocEx>WriteProcessMemory>NtCreateThreadEx".to_string()),
        timestamp: 1300,
    };

    let alert =
        anxin_security::services::hook_service::InjectionChainAlert::from_blocked_hook_event(
            &event,
        )
        .expect("blocked NtCreateThreadEx hook notice should directly alert");

    assert_eq!(alert.source_pid, 5100);
    assert_eq!(alert.target_pid, 6200);
    assert!(alert.blocked_by_hook);
    assert!(alert.target_suspended_by_hook);
    assert!(alert.apis.iter().any(|api| api == "NtCreateThreadEx"));
}

#[test]
fn injection_chain_tracker_treats_nt_create_thread_ex_as_remote_thread_terminal() {
    let mut tracker = InjectionChainTracker::new(5_000);
    let mut event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("OpenProcess".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("native_injector.exe".to_string()),
        process_path: Some("C:\\Tools\\native_injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: Some(0x2A),
        base_address: None,
        start_address: None,
        size: None,
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    assert!(tracker.record(&event).is_none());

    event.api = Some("VirtualAllocEx".to_string());
    event.timestamp = 1100;
    event.base_address = Some("0x10000000".to_string());
    event.size = Some(1024);
    assert!(tracker.record(&event).is_none());

    event.api = Some("WriteProcessMemory".to_string());
    event.timestamp = 1200;
    assert!(tracker.record(&event).is_none());

    event.api = Some("NtCreateThreadEx".to_string());
    event.timestamp = 1300;
    event.start_address = Some("0x7ff900001234".to_string());
    let alert = tracker
        .record(&event)
        .expect("NtCreateThreadEx should complete the injection chain");

    assert_eq!(alert.source_pid, 5100);
    assert_eq!(alert.target_pid, 6200);
    assert!(alert.apis.iter().any(|api| api == "NtCreateThreadEx"));
}

#[test]
fn injection_chain_tracker_keeps_target_pids_separate() {
    let mut tracker = InjectionChainTracker::new(5_000);
    let mut event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("VirtualAllocEx".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: None,
        process_path: None,
        target_pid: Some(6200),
        desired_access: None,
        base_address: Some("0x1000".to_string()),
        start_address: None,
        size: Some(128),
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    assert!(tracker.record(&event).is_none());
    event.api = Some("WriteProcessMemory".to_string());
    event.timestamp = 1100;
    assert!(tracker.record(&event).is_none());

    event.api = Some("CreateRemoteThread".to_string());
    event.target_pid = Some(7300);
    event.timestamp = 1200;

    assert!(
        tracker.record(&event).is_none(),
        "different target PID must not reuse another target's chain"
    );
}

#[test]
fn single_process_injection_api_risk_event_stays_observational() {
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("WriteProcessMemory".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("file_hook_injector.exe".to_string()),
        process_path: Some("C:\\Tools\\file_hook_injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: None,
        base_address: Some("0x1000".to_string()),
        start_address: None,
        size: Some(128),
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    let app_event = hook_event_to_app_event(&event);
    let risk_event = hook_event_to_risk_event(&event, &app_event);

    assert_eq!(risk_event.threat_type, "api_hook_process_activity");
    assert_eq!(risk_event.rule_id, "API_HOOK_PROCESS_ACTIVITY");
    assert_eq!(risk_event.severity, 20);
    assert!(
        risk_event.file_path.is_none(),
        "单条注入相关 API 不能带源进程路径进入 RiskService，否则未签名注入器会被单点误升为自动拦截"
    );
}

#[test]
fn hook_pipe_wait_retries_only_transient_wait_states() {
    assert!(
        !should_retry_hook_pipe_wait(232),
        "ERROR_NO_DATA means the previous client closed this pipe instance; the server must recreate it"
    );
    assert!(
        should_retry_hook_pipe_read(232),
        "ReadFile can briefly see ERROR_NO_DATA while a cached client connection is still open"
    );
    assert!(
        should_retry_hook_pipe_wait(536),
        "ERROR_PIPE_LISTENING should keep waiting for a client"
    );
    assert!(
        should_retry_hook_pipe_read(536),
        "ReadFile should also tolerate the nonblocking listening state briefly"
    );
    assert!(
        !should_retry_hook_pipe_wait(109),
        "ERROR_BROKEN_PIPE should stop reading the closed pipe"
    );
    assert!(
        !should_retry_hook_pipe_read(109),
        "ERROR_BROKEN_PIPE must release the pipe instance"
    );
    assert!(
        !should_retry_hook_pipe_wait(5),
        "ERROR_ACCESS_DENIED should surface as a real pipe error"
    );
}

#[test]
fn hook_pipe_message_splitter_handles_coalesced_json_objects() {
    let raw = concat!(
        r#"{"type":"hook_notice","source":"detours_process_injection","api":"OpenProcess","pid":5100,"tid":1,"ts":1,"targetPid":6200}"#,
        " ",
        r#"{"type":"hook_notice","source":"detours_process_injection","api":"VirtualAllocEx","pid":5100,"tid":1,"ts":2,"targetPid":6200,"baseAddress":"0x1000","size":224}"#,
    );

    let messages = split_hook_pipe_messages(raw);

    assert_eq!(messages.len(), 2);
    let first = parse_hook_pipe_line(messages[0])
        .expect("first coalesced JSON object should parse")
        .expect("first object should be an event");
    let second = parse_hook_pipe_line(messages[1])
        .expect("second coalesced JSON object should parse")
        .expect("second object should be an event");
    match first {
        HookPipeMessage::Event(event) => assert_eq!(event.api.as_deref(), Some("OpenProcess")),
        HookPipeMessage::Heartbeat => panic!("expected hook event"),
    }
    match second {
        HookPipeMessage::Event(event) => assert_eq!(event.api.as_deref(), Some("VirtualAllocEx")),
        HookPipeMessage::Heartbeat => panic!("expected hook event"),
    }
}

#[test]
fn hook_pipe_rejects_events_when_payload_pid_does_not_match_client_pid() {
    let event = FileHookEvent {
        event_type: "hook_notice".to_string(),
        source: Some("detours_process_injection".to_string()),
        api: Some("OpenProcess".to_string()),
        path: String::new(),
        target_path: None,
        pid: 5100,
        tid: 9,
        process_name: Some("injector.exe".to_string()),
        process_path: Some("C:\\Tools\\injector.exe".to_string()),
        target_pid: Some(6200),
        desired_access: Some(0x2A),
        base_address: None,
        start_address: None,
        size: None,
        blocked: None,
        target_suspended: None,
        last_error: None,
        chain: None,
        timestamp: 1000,
    };

    assert!(should_accept_hook_event_from_client(&event, 5100));
    assert!(!should_accept_hook_event_from_client(&event, 6200));
    assert!(!should_accept_hook_event_from_client(&event, 0));
    assert!(!should_accept_hook_event_from_client(&event, 4));
    assert!(!should_accept_hook_event_from_client(&event, u32::MAX));
}
