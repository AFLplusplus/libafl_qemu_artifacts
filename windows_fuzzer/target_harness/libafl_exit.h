#ifndef LIBAFL_EXIT_H
#define LIBAFL_EXIT_H

#ifdef _DEBUG
#ifndef LIBAFL_MOCK
#define LIBAFL_MOCK
#endif
#endif

// Target Specific imports / definitions
#ifdef _WIN32
#include <stdint.h>
#include <intsafe.h>

typedef UINT64 libafl_word;
#define LIBAFL_CALLING_CONVENTION	__fastcall
#endif

typedef enum LibaflExit {
	LIBAFL_EXIT_START_VIRT			= 0,
	LIBAFL_EXIT_START_PHYS			= 1,
	LIBAFL_EXIT_INPUT_VIRT			= 2,
	LIBAFL_EXIT_INPUT_PHYS			= 3,
	LIBAFL_EXIT_END					= 4,
	LIBAFL_EXIT_SAVE				= 5,
	LIBAFL_EXIT_LOAD				= 6,
	LIBAFL_EXIT_VERSION				= 7,
	LIBAFL_EXIT_VADDR_FILTER_ALLOW  = 8,
} LibaflExit;

typedef enum LibaflExitEndStatus {
	LIBAFL_EXIT_END_UNKNOWN		= 0,
	LIBAFL_EXIT_END_OK			= 1,
	LIBAFL_EXIT_END_CRASH		= 2,
} LibaflExitEndParams;

#ifdef LIBAFL_MOCK
static libafl_word libafl_mock_command_handler(libafl_word action, libafl_word arg1, libafl_word arg2)
{
	switch (action) {
	case LIBAFL_EXIT_START_VIRT: {
		std::cout << "LibAFL: Start with virtual address." << std::endl;

		UINT8* input = (UINT8*)arg1;
		UINT64 input_len = arg2;

		memset(input, 'A', 128);

		return 128;
	}
	case LIBAFL_EXIT_START_PHYS: {
		std::cout << "LibAFL: Start with physical address." << std::endl;
		
		UINT8* input = (UINT8*)arg1;
		UINT64 input_len = arg2;

		memset(input, 'A', 128);

		return 128;
	}
	case LIBAFL_EXIT_INPUT_VIRT: {
		std::cout << "LibAFL: get input at physical address." << std::endl;
		
		UINT8* input = (UINT8*)arg1;
		UINT64 input_len = arg2;

		memset(input, 'A', 128);

		return 128;
	}
	case LIBAFL_EXIT_INPUT_PHYS: {
		std::cout << "LibAFL: get input at virtual address." << std::endl;

		UINT8* input = (UINT8*)arg1;
		UINT64 input_len = arg2;

		memset(input, 'A', 128);

		return 128;
	}
	case LIBAFL_EXIT_END: {
		std::cout << "LibAFL: end of run." << std::endl;

		while (true) {
			Sleep(100);
		}
	}
	case LIBAFL_EXIT_SAVE: {
		std::cout << "LibAFL: save snapshot." << std::endl;
		return 0;
	}
	case LIBAFL_EXIT_LOAD: {
		std::cout << "LibAFL: load snapshot." << std::endl;
		return 0;
	}
	case LIBAFL_EXIT_VADDR_FILTER_ALLOW: {
		printf("LibAFL: track vaddr range  0x%llx -> 0x%llx (len 0x%llx)\n", arg1, arg2, arg2 - arg1);
		return 0;
	}
	default: {
		std::cout << "LibAFL command not found." << std::endl;
		exit(1);
	}
	}
}

libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call0(libafl_word action) { return libafl_mock_command_handler(action, 0, 0); }
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call1(libafl_word action, libafl_word arg1) { return libafl_mock_command_handler(action, arg1, 0); }
libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call2(libafl_word action, libafl_word arg1, libafl_word arg2) { return libafl_mock_command_handler(action, arg1, arg2); }
#else
#ifdef __cplusplus
extern "C" {
#endif
	libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call0(libafl_word action);
	libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call1(libafl_word action, libafl_word arg1);
	libafl_word LIBAFL_CALLING_CONVENTION _libafl_exit_call2(libafl_word action, libafl_word arg1, libafl_word arg2);
#ifdef __cplusplus
}
#endif
#endif

#define LIBAFL_EXIT_START_VIRT(buf_vaddr, max_len)				_libafl_exit_call2(LIBAFL_EXIT_START_VIRT, input_vaddr, max_len)
#define LIBAFL_EXIT_START_PHYS(buf_paddr, max_len)				_libafl_exit_call2(LIBAFL_EXIT_START_PHYS, input_paddr, max_len)
#define LIBAFL_EXIT_INPUT_VIRT(buf_vaddr, max_len)				_libafl_exit_call2(LIBAFL_EXIT_INPUT_VIRT, input_vaddr, max_len)
#define LIBAFL_EXIT_INPUT_PHYS(buf_paddr, max_len)				_libafl_exit_call2(LIBAFL_EXIT_INPUT_PHYS, input_paddr, max_len)
#define LIBAFL_EXIT_END(status)									_libafl_exit_call1(LIBAFL_EXIT_END, status)
#define LIBAFL_EXIT_SAVE()										_libafl_exit_call0(LIBAFL_EXIT_SAVE)
#define LIBAFL_EXIT_LOAD()										_libafl_exit_call0(LIBAFL_EXIT_LOAD)
#define LIBAFL_EXIT_VADDR_FILTER_ALLOW(start_vaddr, end_vaddr)	_libafl_exit_call2(LIBAFL_EXIT_VADDR_FILTER_ALLOW, start_vaddr, end_vaddr)

#ifdef _DEBUG

#endif

#endif