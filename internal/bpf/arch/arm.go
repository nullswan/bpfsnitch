// AUTOGENERATED FILE

//go:build arm
// +build arm

package bpfarch

const BpfProgramElf = bpfProgramName + "_arm.o"

var SyscallToId = map[string]int{
	"restart_syscall":        0,
	"exit":                   1,
	"fork":                   2,
	"read":                   3,
	"write":                  4,
	"open":                   5,
	"close":                  6,
	"creat":                  8,
	"link":                   9,
	"unlink":                 10,
	"execve":                 11,
	"chdir":                  12,
	"mknod":                  14,
	"chmod":                  15,
	"lchown":                 16,
	"lseek":                  19,
	"getpid":                 20,
	"mount":                  21,
	"setuid":                 23,
	"getuid":                 24,
	"ptrace":                 26,
	"pause":                  29,
	"access":                 33,
	"nice":                   34,
	"sync":                   36,
	"kill":                   37,
	"rename":                 38,
	"mkdir":                  39,
	"rmdir":                  40,
	"dup":                    41,
	"pipe":                   42,
	"times":                  43,
	"brk":                    45,
	"setgid":                 46,
	"getgid":                 47,
	"geteuid":                49,
	"getegid":                50,
	"acct":                   51,
	"umount2":                52,
	"ioctl":                  54,
	"fcntl":                  55,
	"setpgid":                57,
	"umask":                  60,
	"chroot":                 61,
	"ustat":                  62,
	"dup2":                   63,
	"getppid":                64,
	"getpgrp":                65,
	"setsid":                 66,
	"sigaction":              67,
	"setreuid":               70,
	"setregid":               71,
	"sigsuspend":             72,
	"sigpending":             73,
	"sethostname":            74,
	"setrlimit":              75,
	"getrusage":              77,
	"gettimeofday":           78,
	"settimeofday":           79,
	"getgroups":              80,
	"setgroups":              81,
	"symlink":                83,
	"readlink":               85,
	"uselib":                 86,
	"swapon":                 87,
	"reboot":                 88,
	"munmap":                 91,
	"truncate":               92,
	"ftruncate":              93,
	"fchmod":                 94,
	"fchown":                 95,
	"getpriority":            96,
	"setpriority":            97,
	"statfs":                 99,
	"fstatfs":                100,
	"syslog":                 103,
	"setitimer":              104,
	"getitimer":              105,
	"stat":                   106,
	"lstat":                  107,
	"fstat":                  108,
	"vhangup":                111,
	"wait4":                  114,
	"swapoff":                115,
	"sysinfo":                116,
	"fsync":                  118,
	"sigreturn":              119,
	"clone":                  120,
	"setdomainname":          121,
	"uname":                  122,
	"adjtimex":               124,
	"mprotect":               125,
	"sigprocmask":            126,
	"init_module":            128,
	"delete_module":          129,
	"quotactl":               131,
	"getpgid":                132,
	"fchdir":                 133,
	"bdflush":                134,
	"sysfs":                  135,
	"personality":            136,
	"setfsuid":               138,
	"setfsgid":               139,
	"_llseek":                140,
	"getdents":               141,
	"flock":                  143,
	"msync":                  144,
	"readv":                  145,
	"writev":                 146,
	"getsid":                 147,
	"fdatasync":              148,
	"mlock":                  150,
	"munlock":                151,
	"mlockall":               152,
	"munlockall":             153,
	"sched_setparam":         154,
	"sched_getparam":         155,
	"sched_setscheduler":     156,
	"sched_getscheduler":     157,
	"sched_yield":            158,
	"sched_get_priority_max": 159,
	"sched_get_priority_min": 160,
	"sched_rr_get_interval":  161,
	"nanosleep":              162,
	"mremap":                 163,
	"setresuid":              164,
	"getresuid":              165,
	"poll":                   168,
	"nfsservctl":             169,
	"setresgid":              170,
	"getresgid":              171,
	"prctl":                  172,
	"rt_sigreturn":           173,
	"rt_sigaction":           174,
	"rt_sigprocmask":         175,
	"rt_sigpending":          176,
	"rt_sigtimedwait":        177,
	"rt_sigqueueinfo":        178,
	"rt_sigsuspend":          179,
	"pread64":                180,
	"pwrite64":               181,
	"chown":                  182,
	"getcwd":                 183,
	"capget":                 184,
	"capset":                 185,
	"sigaltstack":            186,
	"sendfile":               187,
	"vfork":                  190,
	"ugetrlimit":             191,
	"mmap2":                  192,
	"truncate64":             193,
	"ftruncate64":            194,
	"stat64":                 195,
	"lstat64":                196,
	"fstat64":                197,
	"lchown32":               198,
	"getuid32":               199,
	"getgid32":               200,
	"geteuid32":              201,
	"getegid32":              202,
	"setreuid32":             203,
	"setregid32":             204,
	"getgroups32":            205,
	"setgroups32":            206,
	"fchown32":               207,
	"setresuid32":            208,
	"getresuid32":            209,
	"setresgid32":            210,
	"getresgid32":            211,
	"chown32":                212,
	"setuid32":               213,
	"setgid32":               214,
	"setfsuid32":             215,
	"setfsgid32":             216,
	"getdents64":             217,
	"pivot_root":             218,
	"mincore":                219,
	"madvise":                220,
	"fcntl64":                221,
	"gettid":                 224,
	"readahead":              225,
	"setxattr":               226,
	"lsetxattr":              227,
	"fsetxattr":              228,
	"getxattr":               229,
	"lgetxattr":              230,
	"fgetxattr":              231,
	"listxattr":              232,
	"llistxattr":             233,
	"flistxattr":             234,
	"removexattr":            235,
	"lremovexattr":           236,
	"fremovexattr":           237,
	"tkill":                  238,
	"sendfile64":             239,
	"futex":                  240,
	"sched_setaffinity":      241,
	"sched_getaffinity":      242,
	"io_setup":               243,
	"io_destroy":             244,
	"io_getevents":           245,
	"io_submit":              246,
	"io_cancel":              247,
	"exit_group":             248,
	"lookup_dcookie":         249,
	"epoll_create":           250,
	"epoll_ctl":              251,
	"epoll_wait":             252,
	"remap_file_pages":       253,
	"set_tid_address":        256,
	"timer_create":           257,
	"timer_settime":          258,
	"timer_gettime":          259,
	"timer_getoverrun":       260,
	"timer_delete":           261,
	"clock_settime":          262,
	"clock_gettime":          263,
	"clock_getres":           264,
	"clock_nanosleep":        265,
	"statfs64":               266,
	"fstatfs64":              267,
	"tgkill":                 268,
	"utimes":                 269,
	"arm_fadvise64_64":       270,
	"pciconfig_iobase":       271,
	"pciconfig_read":         272,
	"pciconfig_write":        273,
	"mq_open":                274,
	"mq_unlink":              275,
	"mq_timedsend":           276,
	"mq_timedreceive":        277,
	"mq_notify":              278,
	"mq_getsetattr":          279,
	"waitid":                 280,
	"socket":                 281,
	"bind":                   282,
	"connect":                283,
	"listen":                 284,
	"accept":                 285,
	"getsockname":            286,
	"getpeername":            287,
	"socketpair":             288,
	"send":                   289,
	"sendto":                 290,
	"recv":                   291,
	"recvfrom":               292,
	"shutdown":               293,
	"setsockopt":             294,
	"getsockopt":             295,
	"sendmsg":                296,
	"recvmsg":                297,
	"semop":                  298,
	"semget":                 299,
	"semctl":                 300,
	"msgsnd":                 301,
	"msgrcv":                 302,
	"msgget":                 303,
	"msgctl":                 304,
	"shmat":                  305,
	"shmdt":                  306,
	"shmget":                 307,
	"shmctl":                 308,
	"add_key":                309,
	"request_key":            310,
	"keyctl":                 311,
	"semtimedop":             312,
	"vserver":                313,
	"ioprio_set":             314,
	"ioprio_get":             315,
	"inotify_init":           316,
	"inotify_add_watch":      317,
	"inotify_rm_watch":       318,
	"mbind":                  319,
	"get_mempolicy":          320,
	"set_mempolicy":          321,
	"openat":                 322,
	"mkdirat":                323,
	"mknodat":                324,
	"fchownat":               325,
	"futimesat":              326,
	"fstatat64":              327,
	"unlinkat":               328,
	"renameat":               329,
	"linkat":                 330,
	"symlinkat":              331,
	"readlinkat":             332,
	"fchmodat":               333,
	"faccessat":              334,
	"pselect6":               335,
	"ppoll":                  336,
	"unshare":                337,
	"set_robust_list":        338,
	"get_robust_list":        339,
	"splice":                 340,
	"sync_file_range2":       341,
	"tee":                    342,
	"vmsplice":               343,
	"move_pages":             344,
	"getcpu":                 345,
	"epoll_pwait":            346,
	"kexec_load":             347,
	"utimensat":              348,
	"signalfd":               349,
	"timerfd_create":         350,
	"eventfd":                351,
	"fallocate":              352,
	"timerfd_settime":        353,
	"timerfd_gettime":        354,
	"signalfd4":              355,
	"eventfd2":               356,
	"epoll_create1":          357,
	"dup3":                   358,
	"pipe2":                  359,
	"inotify_init1":          360,
	"preadv":                 361,
	"pwritev":                362,
	"rt_tgsigqueueinfo":      363,
	"perf_event_open":        364,
	"recvmmsg":               365,
	"accept4":                366,
	"fanotify_init":          367,
	"fanotify_mark":          368,
	"prlimit64":              369,
	"name_to_handle_at":      370,
	"open_by_handle_at":      371,
	"clock_adjtime":          372,
	"syncfs":                 373,
	"sendmmsg":               374,
	"setns":                  375,
	"process_vm_readv":       376,
	"process_vm_writev":      377,
	"kcmp":                   378,
	"finit_module":           379,
	"sched_setattr":          380,
	"sched_getattr":          381,
	"renameat2":              382,
	"seccomp":                383,
	"getrandom":              384,
	"memfd_create":           385,
	"bpf":                    386,
	"execveat":               387,
	"userfaultfd":            388,
	"membarrier":             389,
	"mlock2":                 390,
	"copy_file_range":        391,
	"preadv2":                392,
	"pwritev2":               393,
	"pkey_mprotect":          394,
	"pkey_alloc":             395,
	"pkey_free":              396,
	"statx":                  397,
	"ARM_breakpoint":         983041,
	"ARM_cacheflush":         983042,
	"ARM_usr26":              983043,
	"ARM_usr32":              983044,
	"ARM_set_tls":            983045,
}

var IdToSyscall = map[int]string{
	0:      "restart_syscall",
	1:      "exit",
	2:      "fork",
	3:      "read",
	4:      "write",
	5:      "open",
	6:      "close",
	8:      "creat",
	9:      "link",
	10:     "unlink",
	11:     "execve",
	12:     "chdir",
	14:     "mknod",
	15:     "chmod",
	16:     "lchown",
	19:     "lseek",
	20:     "getpid",
	21:     "mount",
	23:     "setuid",
	24:     "getuid",
	26:     "ptrace",
	29:     "pause",
	33:     "access",
	34:     "nice",
	36:     "sync",
	37:     "kill",
	38:     "rename",
	39:     "mkdir",
	40:     "rmdir",
	41:     "dup",
	42:     "pipe",
	43:     "times",
	45:     "brk",
	46:     "setgid",
	47:     "getgid",
	49:     "geteuid",
	50:     "getegid",
	51:     "acct",
	52:     "umount2",
	54:     "ioctl",
	55:     "fcntl",
	57:     "setpgid",
	60:     "umask",
	61:     "chroot",
	62:     "ustat",
	63:     "dup2",
	64:     "getppid",
	65:     "getpgrp",
	66:     "setsid",
	67:     "sigaction",
	70:     "setreuid",
	71:     "setregid",
	72:     "sigsuspend",
	73:     "sigpending",
	74:     "sethostname",
	75:     "setrlimit",
	77:     "getrusage",
	78:     "gettimeofday",
	79:     "settimeofday",
	80:     "getgroups",
	81:     "setgroups",
	83:     "symlink",
	85:     "readlink",
	86:     "uselib",
	87:     "swapon",
	88:     "reboot",
	91:     "munmap",
	92:     "truncate",
	93:     "ftruncate",
	94:     "fchmod",
	95:     "fchown",
	96:     "getpriority",
	97:     "setpriority",
	99:     "statfs",
	100:    "fstatfs",
	103:    "syslog",
	104:    "setitimer",
	105:    "getitimer",
	106:    "stat",
	107:    "lstat",
	108:    "fstat",
	111:    "vhangup",
	114:    "wait4",
	115:    "swapoff",
	116:    "sysinfo",
	118:    "fsync",
	119:    "sigreturn",
	120:    "clone",
	121:    "setdomainname",
	122:    "uname",
	124:    "adjtimex",
	125:    "mprotect",
	126:    "sigprocmask",
	128:    "init_module",
	129:    "delete_module",
	131:    "quotactl",
	132:    "getpgid",
	133:    "fchdir",
	134:    "bdflush",
	135:    "sysfs",
	136:    "personality",
	138:    "setfsuid",
	139:    "setfsgid",
	140:    "_llseek",
	141:    "getdents",
	143:    "flock",
	144:    "msync",
	145:    "readv",
	146:    "writev",
	147:    "getsid",
	148:    "fdatasync",
	150:    "mlock",
	151:    "munlock",
	152:    "mlockall",
	153:    "munlockall",
	154:    "sched_setparam",
	155:    "sched_getparam",
	156:    "sched_setscheduler",
	157:    "sched_getscheduler",
	158:    "sched_yield",
	159:    "sched_get_priority_max",
	160:    "sched_get_priority_min",
	161:    "sched_rr_get_interval",
	162:    "nanosleep",
	163:    "mremap",
	164:    "setresuid",
	165:    "getresuid",
	168:    "poll",
	169:    "nfsservctl",
	170:    "setresgid",
	171:    "getresgid",
	172:    "prctl",
	173:    "rt_sigreturn",
	174:    "rt_sigaction",
	175:    "rt_sigprocmask",
	176:    "rt_sigpending",
	177:    "rt_sigtimedwait",
	178:    "rt_sigqueueinfo",
	179:    "rt_sigsuspend",
	180:    "pread64",
	181:    "pwrite64",
	182:    "chown",
	183:    "getcwd",
	184:    "capget",
	185:    "capset",
	186:    "sigaltstack",
	187:    "sendfile",
	190:    "vfork",
	191:    "ugetrlimit",
	192:    "mmap2",
	193:    "truncate64",
	194:    "ftruncate64",
	195:    "stat64",
	196:    "lstat64",
	197:    "fstat64",
	198:    "lchown32",
	199:    "getuid32",
	200:    "getgid32",
	201:    "geteuid32",
	202:    "getegid32",
	203:    "setreuid32",
	204:    "setregid32",
	205:    "getgroups32",
	206:    "setgroups32",
	207:    "fchown32",
	208:    "setresuid32",
	209:    "getresuid32",
	210:    "setresgid32",
	211:    "getresgid32",
	212:    "chown32",
	213:    "setuid32",
	214:    "setgid32",
	215:    "setfsuid32",
	216:    "setfsgid32",
	217:    "getdents64",
	218:    "pivot_root",
	219:    "mincore",
	220:    "madvise",
	221:    "fcntl64",
	224:    "gettid",
	225:    "readahead",
	226:    "setxattr",
	227:    "lsetxattr",
	228:    "fsetxattr",
	229:    "getxattr",
	230:    "lgetxattr",
	231:    "fgetxattr",
	232:    "listxattr",
	233:    "llistxattr",
	234:    "flistxattr",
	235:    "removexattr",
	236:    "lremovexattr",
	237:    "fremovexattr",
	238:    "tkill",
	239:    "sendfile64",
	240:    "futex",
	241:    "sched_setaffinity",
	242:    "sched_getaffinity",
	243:    "io_setup",
	244:    "io_destroy",
	245:    "io_getevents",
	246:    "io_submit",
	247:    "io_cancel",
	248:    "exit_group",
	249:    "lookup_dcookie",
	250:    "epoll_create",
	251:    "epoll_ctl",
	252:    "epoll_wait",
	253:    "remap_file_pages",
	256:    "set_tid_address",
	257:    "timer_create",
	258:    "timer_settime",
	259:    "timer_gettime",
	260:    "timer_getoverrun",
	261:    "timer_delete",
	262:    "clock_settime",
	263:    "clock_gettime",
	264:    "clock_getres",
	265:    "clock_nanosleep",
	266:    "statfs64",
	267:    "fstatfs64",
	268:    "tgkill",
	269:    "utimes",
	270:    "arm_fadvise64_64",
	271:    "pciconfig_iobase",
	272:    "pciconfig_read",
	273:    "pciconfig_write",
	274:    "mq_open",
	275:    "mq_unlink",
	276:    "mq_timedsend",
	277:    "mq_timedreceive",
	278:    "mq_notify",
	279:    "mq_getsetattr",
	280:    "waitid",
	281:    "socket",
	282:    "bind",
	283:    "connect",
	284:    "listen",
	285:    "accept",
	286:    "getsockname",
	287:    "getpeername",
	288:    "socketpair",
	289:    "send",
	290:    "sendto",
	291:    "recv",
	292:    "recvfrom",
	293:    "shutdown",
	294:    "setsockopt",
	295:    "getsockopt",
	296:    "sendmsg",
	297:    "recvmsg",
	298:    "semop",
	299:    "semget",
	300:    "semctl",
	301:    "msgsnd",
	302:    "msgrcv",
	303:    "msgget",
	304:    "msgctl",
	305:    "shmat",
	306:    "shmdt",
	307:    "shmget",
	308:    "shmctl",
	309:    "add_key",
	310:    "request_key",
	311:    "keyctl",
	312:    "semtimedop",
	313:    "vserver",
	314:    "ioprio_set",
	315:    "ioprio_get",
	316:    "inotify_init",
	317:    "inotify_add_watch",
	318:    "inotify_rm_watch",
	319:    "mbind",
	320:    "get_mempolicy",
	321:    "set_mempolicy",
	322:    "openat",
	323:    "mkdirat",
	324:    "mknodat",
	325:    "fchownat",
	326:    "futimesat",
	327:    "fstatat64",
	328:    "unlinkat",
	329:    "renameat",
	330:    "linkat",
	331:    "symlinkat",
	332:    "readlinkat",
	333:    "fchmodat",
	334:    "faccessat",
	335:    "pselect6",
	336:    "ppoll",
	337:    "unshare",
	338:    "set_robust_list",
	339:    "get_robust_list",
	340:    "splice",
	341:    "sync_file_range2",
	342:    "tee",
	343:    "vmsplice",
	344:    "move_pages",
	345:    "getcpu",
	346:    "epoll_pwait",
	347:    "kexec_load",
	348:    "utimensat",
	349:    "signalfd",
	350:    "timerfd_create",
	351:    "eventfd",
	352:    "fallocate",
	353:    "timerfd_settime",
	354:    "timerfd_gettime",
	355:    "signalfd4",
	356:    "eventfd2",
	357:    "epoll_create1",
	358:    "dup3",
	359:    "pipe2",
	360:    "inotify_init1",
	361:    "preadv",
	362:    "pwritev",
	363:    "rt_tgsigqueueinfo",
	364:    "perf_event_open",
	365:    "recvmmsg",
	366:    "accept4",
	367:    "fanotify_init",
	368:    "fanotify_mark",
	369:    "prlimit64",
	370:    "name_to_handle_at",
	371:    "open_by_handle_at",
	372:    "clock_adjtime",
	373:    "syncfs",
	374:    "sendmmsg",
	375:    "setns",
	376:    "process_vm_readv",
	377:    "process_vm_writev",
	378:    "kcmp",
	379:    "finit_module",
	380:    "sched_setattr",
	381:    "sched_getattr",
	382:    "renameat2",
	383:    "seccomp",
	384:    "getrandom",
	385:    "memfd_create",
	386:    "bpf",
	387:    "execveat",
	388:    "userfaultfd",
	389:    "membarrier",
	390:    "mlock2",
	391:    "copy_file_range",
	392:    "preadv2",
	393:    "pwritev2",
	394:    "pkey_mprotect",
	395:    "pkey_alloc",
	396:    "pkey_free",
	397:    "statx",
	983041: "ARM_breakpoint",
	983042: "ARM_cacheflush",
	983043: "ARM_usr26",
	983044: "ARM_usr32",
	983045: "ARM_set_tls",
}

var WhitelistedSyscalls = []int{
	SyscallToId["restart_syscall"],
	SyscallToId["exit"],
	SyscallToId["fork"],
	SyscallToId["creat"],
	SyscallToId["link"],
	SyscallToId["unlink"],
	SyscallToId["execve"],
	SyscallToId["mknod"],
	SyscallToId["ptrace"],
	SyscallToId["setuid"],
	SyscallToId["getuid"],
	SyscallToId["setgid"],
	SyscallToId["getgid"],
	SyscallToId["seteuid"],
	SyscallToId["getegid"],
	SyscallToId["setpgid"],
	SyscallToId["setreuid"],
	SyscallToId["setregid"],
	SyscallToId["setresuid"],
	SyscallToId["getresuid"],
	SyscallToId["setresgid"],
	SyscallToId["getresgid"],
	SyscallToId["prctl"],
	SyscallToId["capget"],
	SyscallToId["capset"],
	SyscallToId["seccomp"],
	SyscallToId["setns"],
	SyscallToId["unshare"],
	SyscallToId["chroot"],
	SyscallToId["mount"],
	SyscallToId["umount2"],
	SyscallToId["pivot_root"],
	SyscallToId["clone"],
	SyscallToId["wait4"],
	SyscallToId["kill"],
	SyscallToId["nice"],
	SyscallToId["kill"],
	SyscallToId["tkill"],
	SyscallToId["tgkill"],
	SyscallToId["socket"],
	SyscallToId["bind"],
	SyscallToId["connect"],
	SyscallToId["listen"],
	SyscallToId["accept"],
	SyscallToId["accept4"],
	SyscallToId["getsockname"],
	SyscallToId["getpeername"],
	SyscallToId["socketpair"],
	SyscallToId["sendto"],
	SyscallToId["recvfrom"],
	SyscallToId["sendmsg"],
	SyscallToId["recvmsg"],
	SyscallToId["getsockopt"],
	SyscallToId["setsockopt"],
	SyscallToId["shutdown"],
	SyscallToId["sendmmsg"],
	SyscallToId["sethostname"],
	SyscallToId["setdomainname"],
}
