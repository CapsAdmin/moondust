local ffi = require("ffi")
ffi.cdef[[
    struct sigaction {
        void (*sa_handler)(int, void*, void*);
        void (*sa_sigaction)(int, void*, void*);
        unsigned long sa_flags;
        void (*sa_restorer)(void);
        unsigned char sa_mask[128];
    };

    int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
    void sigemptyset(unsigned char *set);
]]
ffi.cdef[[
    struct _fpstate {
        uint16_t cwd;
        uint16_t swd;
        uint16_t ftw;
        uint16_t fop;
        uint64_t rip;
        uint64_t rdp;
        uint32_t mxcsr;
        uint32_t mxcr_mask;
        uint32_t st_space[32];
        uint32_t xmm_space[64];
        uint32_t padding[24];
    };
    struct stack_t {
        void *ss_sp;
        int ss_flags;
        size_t ss_size;
    } ;


    struct sigcontext {
        unsigned long r8;
        unsigned long r9;
        unsigned long r10;
        unsigned long r11;
        unsigned long r12;
        unsigned long r13;
        unsigned long r14;
        unsigned long r15;
        unsigned long rdi;
        unsigned long rsi;
        unsigned long rbp;
        unsigned long rbx;
        unsigned long rdx;
        unsigned long rax;
        unsigned long rcx;
        unsigned long rsp;
        unsigned long rip;
        unsigned long eflags;
        unsigned short cs;
        unsigned short gs;
        unsigned short fs;
        unsigned short __pad0;
        unsigned long err;
        unsigned long trapno;
        unsigned long oldmask;
        unsigned long cr2;
        struct _fpstate *fpstate;
        unsigned long __reserved1[8];
    };

    struct ucontext {
        unsigned long uc_flags;
        struct ucontext *uc_link;
        struct stack_t uc_stack;
        struct sigcontext uc_mcontext;
        unsigned long uc_sigmask;
        struct _fpstate __fpregs_mem;
    };
]]
return function(Assembler)
	local SIGTRAP = 5
	local SA_SIGINFO = 4
	local callbacks = {}

	local function debug_handler(signo, info, context)
		local uc = ffi.cast("struct ucontext*", context)
		local cb = table.remove(callbacks, 1)
		cb(
			{
				rax = uc.uc_mcontext.rax,
				rbx = uc.uc_mcontext.rbx,
				rcx = uc.uc_mcontext.rcx,
				rdx = uc.uc_mcontext.rdx,
				rsi = uc.uc_mcontext.rsi,
				rdi = uc.uc_mcontext.rdi,
				rbp = uc.uc_mcontext.rbp,
				rsp = uc.uc_mcontext.rsp,
				rip = uc.uc_mcontext.rip,
				r8 = uc.uc_mcontext.r8,
				r9 = uc.uc_mcontext.r9,
				r10 = uc.uc_mcontext.r10,
				r11 = uc.uc_mcontext.r11,
				r12 = uc.uc_mcontext.r12,
				r13 = uc.uc_mcontext.r13,
				r14 = uc.uc_mcontext.r14,
				r15 = uc.uc_mcontext.r15,
				eflags = uc.uc_mcontext.eflags,
			}
		)
	end

	local is_setup = false

	local function setup()
		if is_setup then return end

		local sa = ffi.new("struct sigaction")
		sa.sa_handler = debug_handler
		sa.sa_flags = SA_SIGINFO
		ffi.C.sigemptyset(sa.sa_mask)

		if ffi.C.sigaction(SIGTRAP, sa, nil) == -1 then
			error("Failed to set up debug handler")
		end

		is_setup = true
	end

	function Assembler:debug(cb)
		setup()
		table.insert(callbacks, cb)
		self:emit(0xCC) -- int3
	end
end
