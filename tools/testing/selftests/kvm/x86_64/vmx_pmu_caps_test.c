// SPDX-License-Identifier: GPL-2.0
/*
 * Test for VMX-pmu perf capability msr
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Test to check the effect of various CPUID settings on
 * MSR_IA32_PERF_CAPABILITIES MSR, and check that what
 * we write with KVM_SET_MSR is _not_ modified by the guest
 * and check it can be retrieved with KVM_GET_MSR, also test
 * the invalid LBR formats are rejected.
 */

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <sys/ioctl.h>
#include <pthread.h>

#include "kvm_util.h"
#include "vmx.h"

#define PMU_CAP_FW_WRITES	(1ULL << 13)
#define PMU_CAP_LBR_FMT		0x3f
union cpuid10_eax {
	struct {
		unsigned int version_id:8;
		unsigned int num_counters:8;
		unsigned int bit_width:8;
		unsigned int mask_length:8;
	} split;
	unsigned int full;
};

union perf_capabilities {
	struct {
		u64	lbr_format:6;
		u64	pebs_trap:1;
		u64	pebs_arch_reg:1;
		u64	pebs_format:4;
		u64	smm_freeze:1;
		u64	full_width_write:1;
		u64 pebs_baseline:1;
		u64	perf_metrics:1;
		u64	pebs_output_pt_available:1;
		u64	anythread_deprecated:1;
	};
	u64	capabilities;
};

static struct kvm_vm *vm;
static struct kvm_vcpu *vcpu;

static void guest_code(void)
{
	wrmsr(MSR_IA32_PERF_CAPABILITIES, PMU_CAP_LBR_FMT);
}

static void *run_vcpu(void *ignore)
{
	vcpu_run(vcpu);

	TEST_ASSERT(!_vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, 0),
		    "Update PERF_CAPABILITIES after VCPU_RUN didn't fail.");

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t cpu_thread;
	const struct kvm_cpuid_entry2 *entry_a_0;
	union cpuid10_eax eax;
	union perf_capabilities host_cap;
	uint64_t val;

	host_cap.capabilities = kvm_get_feature_msr(MSR_IA32_PERF_CAPABILITIES);
	host_cap.capabilities &= (PMU_CAP_FW_WRITES | PMU_CAP_LBR_FMT);

	/* Create VM */
	vm = vm_create(1);
	vcpu = vm_vcpu_add(vm, 1, guest_code);

	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_PDCM));

	TEST_REQUIRE(kvm_get_cpuid_max_basic() >= 0xa);
	entry_a_0 = kvm_get_supported_cpuid_entry(0xa);

	eax.full = entry_a_0->eax;
	__TEST_REQUIRE(eax.split.version_id, "PMU is not supported by the vCPU");

	/* testcase 1, set capabilities when we have PDCM bit */
	vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, PMU_CAP_FW_WRITES);
	ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_PERF_CAPABILITIES), PMU_CAP_FW_WRITES);

	/* testcase 2, check value zero (which disables all features) is accepted */
	vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, 0);
	ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_PERF_CAPABILITIES), 0);

	/* testcase 3, check valid LBR formats are accepted */
	vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, host_cap.lbr_format);
	ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_PERF_CAPABILITIES), (u64)host_cap.lbr_format);

	/*
	 * Testcase 4, check that an "invalid" LBR format is rejected.  Only an
	 * exact match of the host's format (and 0/disabled) is allowed.
	 */
	for (val = 1; val <= PMU_CAP_LBR_FMT; val++) {
		if (val == host_cap.lbr_format)
			continue;

		TEST_ASSERT(!_vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, val),
			    "Bad LBR FMT = 0x%lx didn't fail", val);
	}

	/* Testcase 5, check whatever use space writes is _not_ modified after VCPU_RUN */
	vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, host_cap.capabilities);

	pthread_create(&cpu_thread, NULL, run_vcpu, NULL);
	pthread_join(cpu_thread, NULL);

	TEST_ASSERT(!_vcpu_set_msr(vcpu, MSR_IA32_PERF_CAPABILITIES, 0),
		    "Update PERF_CAPABILITIES after VCPU_RUN didn't fail.");

	ASSERT_EQ(vcpu_get_msr(vcpu, MSR_IA32_PERF_CAPABILITIES), host_cap.capabilities);

	printf("Completed perf capability tests.\n");
	kvm_vm_free(vm);
	return 0;
}
