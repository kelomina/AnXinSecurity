/*
 * SAL annotation stub for manual cl.exe kernel builds.
 * WDK 28000 sal.h produces syntax incompatible with our build configuration.
 * This file is force-included (/FI) before all translation units.
 */
#pragma once

#ifndef _ANX_SAL_STUB_H
#define _ANX_SAL_STUB_H

/* Prevent the real WDK sal.h from being included */
#define _SAL_VERSION 20
#define __SAL_H_VERSION 20

/* Core SAL annotations used in this project */
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif
#ifndef _Outptr_
#define _Outptr_
#endif
#ifndef _Outptr_opt_
#define _Outptr_opt_
#endif
#ifndef _In_reads_
#define _In_reads_(x)
#endif
#ifndef _Out_writes_
#define _Out_writes_(x)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(x)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(x)
#endif
#ifndef _In_reads_opt_
#define _In_reads_opt_(x)
#endif
#ifndef _Out_writes_opt_
#define _Out_writes_opt_(x)
#endif
#ifndef _Out_writes_to_
#define _Out_writes_to_(x,y)
#endif
#ifndef _Out_writes_bytes_to_
#define _Out_writes_bytes_to_(x,y)
#endif
#ifndef _When_
#define _When_(x,y)
#endif
#ifndef _At_
#define _At_(x,y)
#endif
#ifndef _Success_
#define _Success_(x)
#endif
#ifndef _Must_inspect_result_
#define _Must_inspect_result_
#endif
#ifndef _Check_return_
#define _Check_return_
#endif
#ifndef _IRQL_requires_
#define _IRQL_requires_(x)
#endif
#ifndef _IRQL_requires_max_
#define _IRQL_requires_max_(x)
#endif
#ifndef _IRQL_requires_min_
#define _IRQL_requires_min_(x)
#endif
#ifndef _IRQL_saves_
#define _IRQL_saves_
#endif
#ifndef _IRQL_restores_
#define _IRQL_restores_
#endif
#ifndef _IRQL_raises_
#define _IRQL_raises_(x)
#endif
#ifndef _IRQL_lowers_
#define _IRQL_lowers_(x)
#endif
#ifndef _Acquires_lock_
#define _Acquires_lock_(x)
#endif
#ifndef _Releases_lock_
#define _Releases_lock_(x)
#endif
#ifndef _Requires_lock_held_
#define _Requires_lock_held_(x)
#endif
#ifndef _Requires_lock_not_held_
#define _Requires_lock_not_held_(x)
#endif
#ifndef _Use_decl_annotations_
#define _Use_decl_annotations_
#endif
#ifndef _Function_class_
#define _Function_class_(x)
#endif
#ifndef _Kernel_float_saved_
#define _Kernel_float_saved_
#endif
#ifndef _Kernel_float_restored_
#define _Kernel_float_restored_
#endif
#ifndef _Kernel_float_cleared_
#define _Kernel_float_cleared_
#endif
#ifndef _Reserved_
#define _Reserved_
#endif
#ifndef _Const_
#define _Const_
#endif
#ifndef _Notnull_
#define _Notnull_
#endif
#ifndef _Maybenull_
#define _Maybenull_
#endif
#ifndef _Null_
#define _Null_
#endif
#ifndef _Pre_notnull_
#define _Pre_notnull_
#endif
#ifndef _Post_invalid_
#define _Post_invalid_
#endif
#ifndef _Deref_pre_notnull_
#define _Deref_pre_notnull_
#endif
#ifndef _Deref_post_notnull_
#define _Deref_post_notnull_
#endif
#ifndef _Deref_out_
#define _Deref_out_
#endif
#ifndef _Deref_out_opt_
#define _Deref_out_opt_
#endif
#ifndef _Deref_inout_
#define _Deref_inout_
#endif
#ifndef _Deref_inout_opt_
#define _Deref_inout_opt_
#endif
#ifndef _Field_size_
#define _Field_size_(x)
#endif
#ifndef _Field_size_opt_
#define _Field_size_opt_(x)
#endif
#ifndef _Field_size_bytes_
#define _Field_size_bytes_(x)
#endif
#ifndef _Struct_size_bytes_
#define _Struct_size_bytes_(x)
#endif
#ifndef _Printf_format_string_
#define _Printf_format_string_
#endif
#ifndef _Scanf_format_string_
#define _Scanf_format_string_
#endif
#ifndef _Null_terminated_
#define _Null_terminated_
#endif
#ifndef _NullNull_terminated_
#define _NullNull_terminated_
#endif
#ifndef _Valid_
#define _Valid_
#endif
#ifndef _Notvalid_
#define _Notvalid_
#endif
#ifndef _Pre_valid_
#define _Pre_valid_
#endif
#ifndef _Post_valid_
#define _Post_valid_
#endif
#ifndef _Pre_invalid_
#define _Pre_invalid_
#endif
#ifndef _Writable_
#define _Writable_(x)
#endif
#ifndef _Readable_
#define _Readable_(x)
#endif
#ifndef _Pre_writable_
#define _Pre_writable_(x)
#endif
#ifndef _Post_writable_
#define _Post_writable_(x)
#endif
#ifndef _Pre_readable_
#define _Pre_readable_(x)
#endif
#ifndef _Post_readable_
#define _Post_readable_(x)
#endif
#ifndef _Ret_maybenull_
#define _Ret_maybenull_
#endif
#ifndef _Ret_notnull_
#define _Ret_notnull_
#endif
#ifndef _Post_ptr_invalid_
#define _Post_ptr_invalid_
#endif
#ifndef _Pre_defensive_
#define _Pre_defensive_
#endif
#ifndef _Post_defensive_
#define _Post_defensive_
#endif
#ifndef _In_bound_
#define _In_bound_
#endif
#ifndef _Out_bound_
#define _Out_bound_
#endif
#ifndef _Deref_out_bound_
#define _Deref_out_bound_
#endif
#ifndef _Inout_bound_
#define _Inout_bound_
#endif
#ifndef _Assume_
#define _Assume_(x)
#endif
#ifndef _Analysis_assume_
#define _Analysis_assume_(x)
#endif
#ifndef _Analysis_mode_
#define _Analysis_mode_(x)
#endif
#ifndef _Analysis_noreturn_
#define _Analysis_noreturn_
#endif
#ifndef _Raises_SEH_exception_
#define _Raises_SEH_exception_
#endif
#ifndef _Maybe_raises_SEH_exception_
#define _Maybe_raises_SEH_exception_
#endif
#ifndef _Interlocked_
#define _Interlocked_
#endif
#ifndef _Interlocked_operand_
#define _Interlocked_operand_
#endif
#ifndef _Pre_satisfies_
#define _Pre_satisfies_(x)
#endif
#ifndef _Post_satisfies_
#define _Post_satisfies_(x)
#endif
#ifndef _Satisfies_
#define _Satisfies_(x)
#endif
#ifndef _Return_type_success_
#define _Return_type_success_(x)
#endif
#ifndef _On_failure_
#define _On_failure_(x)
#endif
#ifndef _Always_
#define _Always_(x)
#endif
#ifndef _Group_
#define _Group_(x)
#endif
#ifndef _Pre_
#define _Pre_
#endif
#ifndef _Post_
#define _Post_
#endif
#ifndef _Deref_
#define _Deref_
#endif
#ifndef _Notref_
#define _Notref_
#endif

/* declspec-based SAL that WDK headers may reference */
#ifndef _Declspec_alloc_
#define _Declspec_alloc_(x)
#endif

#endif /* _ANX_SAL_STUB_H */
