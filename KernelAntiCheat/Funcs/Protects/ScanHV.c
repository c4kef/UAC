#include "..\funcs.h"
#include "..\log.h"

static inline unsigned long long rdtsc_diff_vmexit() {
	ULONG64 t1 = __rdtsc();
	int r[4];
	__cpuid(r, 1);
	return __rdtsc() - t1;
}

int cpu_rdtsc_force_vmexit() {
	int i;
	unsigned long long avg = 0;
	for (i = 0; i < 10; i++) {
		avg = avg + rdtsc_diff_vmexit();
		SleepThread(500);
	}
	avg = avg / 10;
	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}

BOOL IsHV()
{
	if (cpu_rdtsc_force_vmexit()) {
		return TRUE;
	}

	__try {
		__vmx_vmread(NULL, NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	return FALSE;
}

BOOL IsLazyHV()
{
	__try
	{
		cr0_t cr0;
		cr0.full = __readcr0();

		cr0.numeric_error = !cr0.numeric_error;
		cr0.protection_enable = 0;

		__writecr0(cr0.full);

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	{
		cr0_t old_cr0;
		old_cr0.full = __readcr0();

		__try
		{
			//_disable();

			{
				cr0_t cr0 = old_cr0;
				cr0.numeric_error = !cr0.numeric_error;
				__writecr0(cr0.full);

				cr0.full = __readcr0();

				if (cr0.numeric_error == old_cr0.numeric_error)
				{
					//_enable();
					return TRUE;
				}
			}

			__writecr0(old_cr0.full);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			//_enable();
			return TRUE;
		}

		//_enable();
	}

	__try
	{
		__writecr4(__readcr4() | (1 << 23));

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	__try
	{
		__writecr0(__readcr0() | (1 << 23));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return TRUE;
	}

	{
		//_disable();

		cr0_t old_cr0;
		old_cr0.full = __readcr0();

		__try
		{
			cr0_t cr0 = old_cr0;
			cr0.numeric_error = !cr0.numeric_error;
			cr0.protection_enable = 0;
			cr0.write_protect = !cr0.write_protect;
			__writecr0(cr0.full);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			cr0_t cr0;
			cr0.full = __readcr0();

			if (cr0.write_protect != old_cr0.write_protect)
			{
				//_enable();

				__writecr0(old_cr0.full);
				return TRUE;
			}
		}

		//_enable();
	}

	return FALSE;
}

BOOL ScanHV()
{
	BOOL isLHV = IsLazyHV();
	BOOL isHV = IsHV();
	if (isLHV)
	{
		DPRINT_LOG("(%s) [DETECT] detected is lazy hypervisor", __FUNCTION__);
	}
	if (isHV)
	{
		DPRINT_LOG("(%s) [DETECT] detected is hypervisor", __FUNCTION__);
	}
	return isLHV || isHV;
}