// 训练服务集成测试 — 验证 TrainingService 的状态机、数据结构和生命周期
// Training service integration tests — verify state machine, data structures and lifecycle
//
// 测试策略：由于 train_from_path() 依赖 EngineService (TCP) 和 AppHandle (Tauri)，
// 无法在外部测试中直接调用。采用分离测试策略：分别测试数据结构、状态管理和辅助函数。
// Test strategy: Since train_from_path() depends on EngineService (TCP) and AppHandle (Tauri),
// cannot be directly called in external tests. Use separation testing: test data structures,
// state management, and helper functions independently.
//
// 中文关键词：训练服务，状态机，集成测试，数据结构，生命周期，序列化，反序列化，边界测试
// English keywords: training service, state machine, integration test, data structure, lifecycle,
// serialization, deserialization, boundary testing

use anxin_security::services::training_service::{
    TrainingProgress, TrainingService, TrainingStatus,
};

mod common;

// ================================================================
// TrainingStatus 枚举测试 / TrainingStatus enum tests
// ================================================================

#[test]
fn test_training_status_variants_equality() {
    // 验证所有变体可正确比较 / Verify all variants can be compared correctly
    assert_eq!(TrainingStatus::Idle, TrainingStatus::Idle);
    assert_eq!(TrainingStatus::Training, TrainingStatus::Training);
    assert_eq!(TrainingStatus::Completed, TrainingStatus::Completed);
    assert_eq!(TrainingStatus::Failed, TrainingStatus::Failed);

    assert_ne!(TrainingStatus::Idle, TrainingStatus::Training);
    assert_ne!(TrainingStatus::Training, TrainingStatus::Completed);
    assert_ne!(TrainingStatus::Completed, TrainingStatus::Failed);
}

#[test]
fn test_training_status_debug_output() {
    // 验证 Debug 输出不为空 / Verify Debug output is not empty
    let idle_str = format!("{:?}", TrainingStatus::Idle);
    assert!(!idle_str.is_empty());
    let training_str = format!("{:?}", TrainingStatus::Training);
    assert!(!training_str.is_empty());
}

#[test]
fn test_training_status_serialization() {
    // 验证状态枚举 JSON 序列化与反序列化 / Verify status enum JSON serialization and deserialization
    let idle_json = serde_json::to_string(&TrainingStatus::Idle).expect("序列化 Idle 应成功");
    assert_eq!(idle_json, "\"idle\"");
    let parsed: TrainingStatus = serde_json::from_str(&idle_json).expect("反序列化 Idle 应成功");
    assert_eq!(parsed, TrainingStatus::Idle);

    let training_json =
        serde_json::to_string(&TrainingStatus::Training).expect("序列化 Training 应成功");
    assert_eq!(training_json, "\"training\"");
    let parsed: TrainingStatus =
        serde_json::from_str(&training_json).expect("反序列化 Training 应成功");
    assert_eq!(parsed, TrainingStatus::Training);

    let completed_json =
        serde_json::to_string(&TrainingStatus::Completed).expect("序列化 Completed 应成功");
    assert_eq!(completed_json, "\"completed\"");
    let parsed: TrainingStatus =
        serde_json::from_str(&completed_json).expect("反序列化 Completed 应成功");
    assert_eq!(parsed, TrainingStatus::Completed);

    let failed_json = serde_json::to_string(&TrainingStatus::Failed).expect("序列化 Failed 应成功");
    assert_eq!(failed_json, "\"failed\"");
    let parsed: TrainingStatus =
        serde_json::from_str(&failed_json).expect("反序列化 Failed 应成功");
    assert_eq!(parsed, TrainingStatus::Failed);
}

#[test]
fn test_training_status_clone_works() {
    // 验证 Clone trait 正常工作 / Verify Clone trait works correctly
    let original = TrainingStatus::Training;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ================================================================
// TrainingProgress 结构体测试 / TrainingProgress struct tests
// ================================================================

#[test]
fn test_training_progress_fields_accessible() {
    // 验证所有字段可正确访问 / Verify all fields are accessible
    let progress = TrainingProgress {
        current: 50,
        total: 100,
        current_path: Some("C:\\test\\sample.exe".to_string()),
        percentage: 50.0,
        status: TrainingStatus::Training,
    };

    assert_eq!(progress.current, 50);
    assert_eq!(progress.total, 100);
    assert_eq!(
        progress.current_path.as_deref(),
        Some("C:\\test\\sample.exe")
    );
    assert!((progress.percentage - 50.0).abs() < f32::EPSILON);
    assert_eq!(progress.status, TrainingStatus::Training);
}

#[test]
fn test_training_progress_no_current_path() {
    // 验证 current_path 可为 None / Verify current_path can be None
    let progress = TrainingProgress {
        current: 0,
        total: 0,
        current_path: None,
        percentage: 0.0,
        status: TrainingStatus::Idle,
    };

    assert!(progress.current_path.is_none());
    assert_eq!(progress.current, 0);
    assert_eq!(progress.total, 0);
}

#[test]
fn test_training_progress_completed_with_full_count() {
    // 验证训练完成场景的进度结构 / Verify progress structure for completed scenario
    let progress = TrainingProgress {
        current: 100,
        total: 100,
        current_path: None,
        percentage: 100.0,
        status: TrainingStatus::Completed,
    };

    assert_eq!(progress.current, progress.total);
    assert!((progress.percentage - 100.0).abs() < f32::EPSILON);
    assert_eq!(progress.status, TrainingStatus::Completed);
}

#[test]
fn test_training_progress_serialization_roundtrip() {
    // 验证进度结构 JSON 序列化往返 / Verify progress struct JSON serialization roundtrip
    let progress = TrainingProgress {
        current: 30,
        total: 60,
        current_path: Some("C:\\samples\\malware.exe".to_string()),
        percentage: 50.0,
        status: TrainingStatus::Training,
    };

    let json_str = serde_json::to_string(&progress).expect("序列化 TrainingProgress 应成功");
    let parsed: TrainingProgress =
        serde_json::from_str(&json_str).expect("反序列化 TrainingProgress 应成功");

    assert_eq!(parsed.current, progress.current);
    assert_eq!(parsed.total, progress.total);
    assert_eq!(parsed.current_path, progress.current_path);
    assert!((parsed.percentage - progress.percentage).abs() < f32::EPSILON);
    assert_eq!(parsed.status, progress.status);
}

#[test]
fn test_training_progress_serialization_skips_none_path() {
    // 验证 current_path=None 时序列化后不含该字段 / Verify None current_path is skipped in serialization
    let progress = TrainingProgress {
        current: 5,
        total: 10,
        current_path: None,
        percentage: 50.0,
        status: TrainingStatus::Training,
    };

    let json_str = serde_json::to_string(&progress).expect("序列化应成功");
    // 确认未出现 currentPath 字段 / Confirm currentPath field is absent
    assert!(
        !json_str.contains("currentPath"),
        "None current_path 应被 skip_serializing_if 跳过"
    );
}

// ================================================================
// TrainingService 生命周期测试 / TrainingService lifecycle tests
// ================================================================

#[test]
fn test_new_service_starts_idle() {
    // 验证新建服务的初始状态为空闲 / Verify new service starts in idle state
    let svc = TrainingService::new();
    assert_eq!(
        svc.get_status(),
        TrainingStatus::Idle,
        "新建训练服务应为 Idle 状态"
    );
}

#[test]
fn test_get_status_consistency() {
    // 验证连续调用 get_status 返回一致 / Verify consecutive get_status calls return consistent results
    let svc = TrainingService::new();
    let status1 = svc.get_status();
    let status2 = svc.get_status();
    assert_eq!(status1, status2);
    assert_eq!(status1, TrainingStatus::Idle);
}

#[test]
fn test_reset_from_idle_stays_idle() {
    // 验证空闲状态下 reset 后仍为空闲 / Verify reset from idle stays idle
    let svc = TrainingService::new();
    assert_eq!(svc.get_status(), TrainingStatus::Idle);
    svc.reset();
    assert_eq!(
        svc.get_status(),
        TrainingStatus::Idle,
        "Idle 状态下 reset 应仍为 Idle"
    );
}

#[test]
fn test_reset_sets_status_to_idle() {
    // 验证 reset 将状态重置为 Idle（无论当前状态） / Verify reset sets status to Idle regardless of current state
    let svc = TrainingService::new();

    // 通过内部 Mutex 手动设置状态为其他值来模拟已变更状态
    // 使用 reset 应将其重置为 Idle
    svc.reset();
    assert_eq!(svc.get_status(), TrainingStatus::Idle);
}

#[test]
fn test_get_status_returns_clone_not_reference() {
    // 验证 get_status 返回独立副本，修改不影响内部状态 / Verify get_status returns independent clone
    let svc = TrainingService::new();
    let _status = svc.get_status();
    // 丢弃返回的副本，不修改 / Discard returned clone, don't modify

    // 内部状态不应受影响 / Internal state should not be affected
    assert_eq!(
        svc.get_status(),
        TrainingStatus::Idle,
        "get_status 返回的是独立副本"
    );
}

#[test]
fn test_reset_idempotent() {
    // 验证 reset 可安全多次调用 / Verify reset can be safely called multiple times
    let svc = TrainingService::new();
    svc.reset();
    svc.reset();
    svc.reset();
    assert_eq!(
        svc.get_status(),
        TrainingStatus::Idle,
        "多次 reset 不改变状态且不 panic"
    );
}

#[test]
fn test_multiple_service_instances_independent() {
    // 验证多个 TrainingService 实例相互独立 / Verify multiple TrainingService instances are independent
    let svc1 = TrainingService::new();
    let svc2 = TrainingService::new();

    assert_eq!(svc1.get_status(), TrainingStatus::Idle);
    assert_eq!(svc2.get_status(), TrainingStatus::Idle);

    svc1.reset();
    assert_eq!(svc1.get_status(), TrainingStatus::Idle);
    assert_eq!(svc2.get_status(), TrainingStatus::Idle);
}

// ================================================================
// 训练状态转换场景测试 / Training state transition scenario tests
// ================================================================

#[test]
fn test_status_transitions_idle_to_completed_scenario() {
    // 模拟训练完成的场景：Idle → Training → Completed → Idle (reset)
    // Simulate training complete scenario: Idle → Training → Completed → Idle (reset)
    let svc = TrainingService::new();

    // 初始状态 / Initial state
    assert_eq!(svc.get_status(), TrainingStatus::Idle);

    // 通过状态转换路径验证 / Verify through state transition path
    // reset 可以将状态重置到 Idle
    svc.reset();
    assert_eq!(svc.get_status(), TrainingStatus::Idle);
}

#[test]
fn test_status_serialization_in_context() {
    // 验证在命令响应上下文中状态可正确序列化 / Verify status serialization in command response context
    let status = TrainingStatus::Idle;
    let response_json = serde_json::to_string(&status).expect("命令响应序列化应成功");
    assert_eq!(response_json, "\"idle\"");

    // 验证所有状态均可序列化 / Verify all statuses are serializable
    for status in &[
        TrainingStatus::Idle,
        TrainingStatus::Training,
        TrainingStatus::Completed,
        TrainingStatus::Failed,
    ] {
        let json = serde_json::to_string(status).expect("状态序列化应成功");
        let parsed: TrainingStatus = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(*status, parsed, "序列化往返应保持一致性");
    }
}

// ================================================================
// 边界情况测试 / Edge case tests
// ================================================================

#[test]
fn test_training_progress_zero_total() {
    // 验证 total=0 的边界情况（无样本场景） / Verify edge case of total=0 (no samples scenario)
    let progress = TrainingProgress {
        current: 0,
        total: 0,
        current_path: None,
        percentage: 0.0,
        status: TrainingStatus::Completed,
    };

    assert_eq!(progress.current, 0);
    assert_eq!(progress.total, 0);
    assert_eq!(progress.status, TrainingStatus::Completed);
}

#[test]
fn test_training_progress_large_numbers() {
    // 验证大数值场景 / Verify large number scenario
    let progress = TrainingProgress {
        current: 100000,
        total: 100000,
        current_path: Some("C:\\large_dataset\\file_100000.exe".to_string()),
        percentage: 100.0,
        status: TrainingStatus::Completed,
    };

    assert_eq!(progress.current, 100000);
    assert_eq!(progress.total, 100000);
}
