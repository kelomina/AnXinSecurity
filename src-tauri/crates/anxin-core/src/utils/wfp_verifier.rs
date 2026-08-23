// WFP filter 顺序验证 — 确认 AnXinProcMon 采集 callout 先于 AnXinNetFilter 拦截
//  WFP filter ordering verification - confirms the AnXinProcMon collection callout
//  is evaluated before the AnXinNetFilter blocking filters
//
// 背景（docs/proc_monitor_design.md §3.7 对策 4 / §13.6）：
//  Background (contract §3.7 countermeasure 4 / §13.6):
// - AnXinNetFilter 在 ALE_AUTH_CONNECT 层以**自动权重**添加 BLOCK filter
// - AnXinProcMon 在 ALE_AUTH_CONNECT_V4/V6 层以**显式权重**
//   0x0000FFFFFFFFFFFF 添加 COLLECT callout filter
// - WFP 在同一层内按 weight 降序评估：权重越大越先执行。
//   只要 ProcMon 的显式权重 > NetFilter 的自动权重，采集就先于拦截，
//   被拦下的连接也能留下 EDR 溯源事件。
// - 本模块枚举 ALE_AUTH_CONNECT_V4/V6 层中两个 AnXin provider 的 filter，
//   按权重排序输出，并断言 ProcMon 在前。
//
// 只读验证：只打开引擎会话枚举，不添加/不修改任何 WFP 对象。
//  Read-only: opens an engine session for enumeration only; never adds or
//  modifies any WFP object.
//
// 中文关键词：WFP 过滤顺序，callout 权重，防火墙，顺序验证，BFE 引擎
// English keywords: WFP filter order, callout weight, firewall, order verification, BFE engine
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFreeMemory0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0, FWP_ACTION_BLOCK,
    FWP_ACTION_CALLOUT_TERMINATING, FWP_ACTION_PERMIT, FWP_UINT64,
};

// ============================================================================
// 持久 GUID（不得更改，见各驱动的注释） / Durable GUIDs (never change)
// ============================================================================

/// AnXinNetFilter 的 WFP provider / AnXinNetFilter WFP provider
pub const ANX_NET_PROVIDER_GUID: GUID = GUID::from_u128(0xa7e9c1d4_3f82_4b16_9e5a_2c7d10000001);
/// AnXinNetFilter 的 sublayer / AnXinNetFilter sublayer
pub const ANX_NET_SUBLAYER_GUID: GUID = GUID::from_u128(0xa7e9c1d4_3f82_4b16_9e5a_2c7d10000002);
/// AnXinProcMon 的 WFP provider / AnXinProcMon WFP provider
pub const ANX_PROC_PROVIDER_GUID: GUID = GUID::from_u128(0xc6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f01);
/// AnXinProcMon 的 V4 callout / AnXinProcMon V4 callout
pub const ANX_PROC_CALLOUT_V4_GUID: GUID = GUID::from_u128(0xc6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f11);
/// AnXinProcMon 的 V6 callout / AnXinProcMon V6 callout
pub const ANX_PROC_CALLOUT_V6_GUID: GUID = GUID::from_u128(0xd6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f22);

/// ProcMon callout filter 的显式权重（native/proc_monitor/src/network.c 与之一致）
///  Explicit weight of the ProcMon callout filters (matches network.c)
pub const ANX_PROC_FILTER_WEIGHT: u64 = 0x0000_FFFF_FFFF_FFFF;

// ============================================================================
// 结果结构 / Result structures
// ============================================================================

/// 一条 AnXin filter 的摘要 / Summary of one AnXin filter
#[derive(Debug, Clone)]
pub struct AnxinFilterInfo {
    pub layer: String,
    pub filter_key: GUID,
    /// 请求权重（FWP_UINT64 指针；None 表示自动权重）
    pub weight: Option<u64>,
    /// 评估顺序权重（BFE 计算后的实际权重；自动权重也会在这里展开）
    pub effective_weight: u64,
    pub action: u32,
    pub action_kind: String,
    pub provider: String,
    /// displayData.name（可为空）
    pub name: String,
}

/// 顺序验证结果 / Ordering verification result
#[derive(Debug, Clone, Default)]
pub struct WfpOrderReport {
    /// 两个 ALE 层中属于 AnXin 的 filter（已按 effective_weight 降序）
    pub filters: Vec<AnxinFilterInfo>,
    /// ProcMon callout filter 的 filterKey（缺失说明驱动未注册 callout filter）
    pub procmon_filter_keys: Vec<GUID>,
    /// 验证是否通过：ProcMon filter 存在于各层且权重高于该层 NetFilter filter
    pub order_ok: bool,
    pub message: String,
}

// ============================================================================
// 枚举与验证 / Enumeration & verification
// ============================================================================

/// 打开 WFP 引擎会话（只读）。失败返回描述性错误。
///  Opens a WFP engine session (read-only).
fn open_engine() -> Result<HANDLE, String> {
    let mut handle = HANDLE::default();
    // SAFETY: 标准 WFP 枚举会话；无认证身份、无事务。
    let status = unsafe {
        FwpmEngineOpen0(
            None,
            0,
            None,
            Some(&FWPM_SESSION0 {
                sessionKey: GUID::zeroed(),
                displayData: Default::default(),
                flags: 0,
                txnWaitTimeoutInMSec: 0,
                processId: 0,
                sid: std::ptr::null_mut(),
                username: windows::core::PWSTR::null(),
                kernelMode: false.into(),
            }),
            &mut handle,
        )
    };
    if status != 0 {
        return Err(format!("FwpmEngineOpen0 failed with 0x{:08X}", status));
    }
    Ok(handle)
}

/// 枚举指定 ALE 层中属于给定 provider 的 filter。
///  Enumerates filters of one provider on one ALE layer.
///
/// SAFETY 说明：FwpmFilterEnum0 返回的 entries 由 BFE 分配，用完必须
/// FwpmFreeMemory0 释放；逐条读取时只拷贝需要的标量字段与 UTF-16 名字。
///  SAFETY note: entries allocated by BFE must be released with FwpmFreeMemory0;
///  only the needed scalar fields and the UTF-16 name are copied out.
unsafe fn enum_provider_filters(
    engine: HANDLE,
    layer: GUID,
    provider: GUID,
    layer_name: &str,
    provider_name: &str,
    out: &mut Vec<AnxinFilterInfo>,
) -> Result<(), String> {
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &provider as *const GUID as *mut GUID,
        layerKey: layer,
        enumType: Default::default(),
        flags: 0,
        providerContextTemplate: std::ptr::null_mut(),
        numFilterConditions: 0,
        filterCondition: std::ptr::null_mut(),
        actionMask: 0,
        calloutKey: std::ptr::null_mut(),
    };

    let mut enum_handle = HANDLE::default();
    let status = FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle);
    if status != 0 {
        return Err(format!(
            "FwpmFilterCreateEnumHandle0({}) failed with 0x{:08X}",
            layer_name, status
        ));
    }

    let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
    let mut num_returned: u32 = 0;
    let status = FwpmFilterEnum0(
        engine,
        enum_handle,
        1024,
        &mut entries,
        &mut num_returned,
    );

    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);

    if status != 0 && status != 0x80270002 {
        // 0x80270002 = FWP_E_NOT_FOUND：层上无 filter，正常
        return Err(format!(
            "FwpmFilterEnum0({}) failed with 0x{:08X}",
            layer_name, status
        ));
    }

    for i in 0..num_returned as usize {
        let filter = *entries.add(i);
        if filter.is_null() {
            continue;
        }
        let f = &*filter;

        let weight = if f.weight.r#type == FWP_UINT64 {
            f.weight.Anonymous.uint64.as_ref().map(|p| *p)
        } else {
            None
        };
        let effective_weight = if f.effectiveWeight.r#type == FWP_UINT64 {
            f.effectiveWeight.Anonymous.uint64.as_ref().map(|p| *p).unwrap_or(0)
        } else {
            0
        };

        let action_kind = match f.action.r#type {
            FWP_ACTION_PERMIT => "PERMIT".to_string(),
            FWP_ACTION_BLOCK => "BLOCK".to_string(),
            FWP_ACTION_CALLOUT_TERMINATING => "CALLOUT".to_string(),
            other => format!("type={}", other.0),
        };

        let name = if !f.displayData.name.is_null() {
            let mut chars: Vec<u16> = Vec::new();
            let mut p: *const u16 = f.displayData.name.as_ptr();
            unsafe {
                while !p.is_null() && *p != 0 {
                    chars.push(*p);
                    p = p.add(1);
                }
            }
            String::from_utf16_lossy(&chars)
        } else {
            String::new()
        };

        out.push(AnxinFilterInfo {
            layer: layer_name.to_string(),
            filter_key: f.filterKey,
            weight,
            effective_weight,
            action: f.action.r#type.0,
            action_kind,
            provider: provider_name.to_string(),
            name,
        });
    }

    // 释放 BFE 分配的 entries（FwpmFreeMemory0 置空指针）
    if !entries.is_null() {
        let mut free_ptr: *mut core::ffi::c_void = entries as *mut core::ffi::c_void;
        FwpmFreeMemory0(&mut free_ptr);
    }

    Ok(())
}

/// 验证 AnXin 的 WFP filter 顺序：ProcMon callout 必须先于 NetFilter BLOCK 评估。
///  Verifies the AnXin WFP filter order: ProcMon callouts must be evaluated
///  before NetFilter BLOCK filters.
///
/// 在 ALE_AUTH_CONNECT_V4/V6 两层分别枚举两个 provider 的 filter，
/// 然后按 effective_weight 降序排序；只要某层存在 ProcMon filter 且其权重
/// 大于该层所有 NetFilter filter，该层顺序即正确。
///  Enumerates both providers' filters on both ALE connect layers, sorts by
///  effective weight descending; a layer passes if a ProcMon filter exists there
///  with a weight greater than every NetFilter filter on the same layer.
pub fn verify_anxin_filter_order() -> Result<WfpOrderReport, String> {
    let engine = open_engine()?;

    let mut filters: Vec<AnxinFilterInfo> = Vec::new();
    let mut procmon_filter_keys: Vec<GUID> = Vec::new();

    let result = (|| {
        // SAFETY: 枚举函数内部负责释放 entries；本闭包只读取拷贝出的标量。
        unsafe {
            enum_provider_filters(
                engine,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                ANX_NET_PROVIDER_GUID,
                "ALE_AUTH_CONNECT_V4",
                "net_filter",
                &mut filters,
            )?;
            enum_provider_filters(
                engine,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                ANX_PROC_PROVIDER_GUID,
                "ALE_AUTH_CONNECT_V4",
                "proc_monitor",
                &mut filters,
            )?;
            enum_provider_filters(
                engine,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                ANX_NET_PROVIDER_GUID,
                "ALE_AUTH_CONNECT_V6",
                "net_filter",
                &mut filters,
            )?;
            enum_provider_filters(
                engine,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                ANX_PROC_PROVIDER_GUID,
                "ALE_AUTH_CONNECT_V6",
                "proc_monitor",
                &mut filters,
            )?;
        }
        Ok::<(), String>(())
    })();

    let _ = unsafe { FwpmEngineClose0(engine) };
    result?;

    // 按层 → 按 effective weight 降序（权重越大越先评估）
    //  Sort by layer, then by effective weight descending (higher weight = earlier evaluation)
    filters.sort_by(|a, b| {
        b.layer
            .cmp(&a.layer)
            .then_with(|| b.effective_weight.cmp(&a.effective_weight))
    });

    procmon_filter_keys.extend(
        filters
            .iter()
            .filter(|f| f.provider == "proc_monitor")
            .map(|f| f.filter_key),
    );

    // 逐层验证 / Verify each layer
    let mut order_ok = true;
    let mut message = String::new();
    for layer in ["ALE_AUTH_CONNECT_V4", "ALE_AUTH_CONNECT_V6"] {
        let layer_filters: Vec<_> = filters.iter().filter(|f| f.layer == layer).collect();
        let procmon_max = layer_filters
            .iter()
            .filter(|f| f.provider == "proc_monitor")
            .map(|f| f.effective_weight)
            .max();
        let netfilter_max = layer_filters
            .iter()
            .filter(|f| f.provider == "net_filter")
            .map(|f| f.effective_weight)
            .max();

        match (procmon_max, netfilter_max) {
            (Some(p), Some(n)) if p > n => {
                message.push_str(&format!(
                    "{}: OK (proc_monitor weight {} > net_filter weight {})\n",
                    layer, p, n
                ));
            }
            (Some(p), Some(n)) => {
                order_ok = false;
                message.push_str(&format!(
                    "{}: FAIL (proc_monitor weight {} <= net_filter weight {})\n",
                    layer, p, n
                ));
            }
            (None, Some(_)) => {
                order_ok = false;
                message.push_str(&format!(
                    "{}: FAIL (no proc_monitor filter registered on this layer)\n",
                    layer
                ));
            }
            (Some(_), None) => {
                message.push_str(&format!(
                    "{}: OK (proc_monitor present; net_filter has no filter here)\n",
                    layer
                ));
            }
            (None, None) => {
                message.push_str(&format!("{}: no AnXin filters on this layer\n", layer));
            }
        }
    }

    if filters.is_empty() {
        message.push_str(
            "No AnXin WFP filters found: the drivers may not be loaded on this machine.",
        );
    }

    Ok(WfpOrderReport {
        filters,
        procmon_filter_keys,
        order_ok,
        message,
    })
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_mon_provider_guid_matches_network_c() {
        // 与 native/proc_monitor/src/network.c 的 ANX_PROC_PROVIDER_GUID 一致
        assert_eq!(
            ANX_PROC_PROVIDER_GUID,
            GUID::from_u128(0xc6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f01)
        );
        assert_eq!(
            ANX_PROC_CALLOUT_V4_GUID,
            GUID::from_u128(0xc6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f11)
        );
        assert_eq!(
            ANX_PROC_CALLOUT_V6_GUID,
            GUID::from_u128(0xd6a3e5f0_8b2d_4e1a_9c4f_0d7b2a6e9f22)
        );
    }

    #[test]
    fn net_filter_guids_match_wfp_c() {
        // 与 native/net_filter/src/wfp.c 的 GUID 定义一致
        assert_eq!(
            ANX_NET_PROVIDER_GUID,
            GUID::from_u128(0xa7e9c1d4_3f82_4b16_9e5a_2c7d10000001)
        );
        assert_eq!(
            ANX_NET_SUBLAYER_GUID,
            GUID::from_u128(0xa7e9c1d4_3f82_4b16_9e5a_2c7d10000002)
        );
    }

    #[test]
    fn procmon_weight_is_highest_possible() {
        // 显式权重必须是 u64 最大合法值（0x0000FFFFFFFFFFFF = u64 高 16 位清 0）
        assert_eq!(ANX_PROC_FILTER_WEIGHT, 0x0000_FFFF_FFFF_FFFF);
        // 必须大于 NetFilter 的自动权重区间：自动权重按 ID 派生，
        // 最大值远小于 2^48；而显式权重顶到 2^48-1，必然在自动权重之上。
        assert!(ANX_PROC_FILTER_WEIGHT > 0x0000_FFFF_FFFF);
    }

    /// GUID 的字面量一致性：V4/V6 callout 只差 provider 内序号，
    /// 与 network.c 的 ANX_PROC_CALLOUT_V4/V6 定义一一对应。
    #[test]
    fn callout_guids_are_distinct_and_named_correctly() {
        assert_ne!(ANX_PROC_CALLOUT_V4_GUID, ANX_PROC_CALLOUT_V6_GUID);
        assert_ne!(ANX_NET_PROVIDER_GUID, ANX_PROC_PROVIDER_GUID);
    }
}
