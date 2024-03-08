/*
Traced syscalls:

close
faccessat
mprotect
openat
prctl
madvise
futex
sched_getscheduler
sigaltstack
getcwd
newfstatat
mmap
munmap
lseek
getrandom
set_tid_address
fstat
mkdirat
readlinkat
statfs
fstatfs
rt_sigaction
pread64
mremap
clock_gettime
fcntl
read

CROSS_CC=/home/andrea/Desktop/hand_on_2/android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang cargo build --release

when using the classic edge cov, add also LIBAFL_EDGES_MAP_SIZE=65536
*/

#![allow(non_upper_case_globals)]

use libafl::prelude::*;
use libafl_bolts::prelude::*;
use libafl_qemu::{
    asan::{init_with_asan, QemuAsanHelper, QemuAsanOptions},
    calls::{FullBacktraceCollector, QemuCallTracerHelper},
    cmplog::{CmpLogObserver, QemuCmpLogHelper, QemuCmpLogRoutinesHelper},
    edges::{
        edges_map_mut_slice, std_edges_map_observer, QemuEdgeCoverageClassicHelper,
        QemuEdgeCoverageHelper, MAX_EDGES_NUM,
    },
    elf::EasyElf,
    emu::Emulator,
    helper::{HasInstrumentationFilter, QemuFilterList, QemuHelper, QemuHelperTuple},
    hooks::QemuHooks,
    snapshot::QemuSnapshotHelper,
    QemuExecutor, Regs, SYS_close, SYS_faccessat, SYS_lseek, SYS_newfstatat, SYS_openat, SYS_read,
    SYS_rt_sigprocmask, SYS_write, SyscallHookResult,
};
use std::{env, ffi::CStr, path::PathBuf, process, ptr, ptr::addr_of_mut, str, time::Duration};

const MAGIC_FD: u64 = 0xabadcafe;
const MAGIC_FILENAME: &'static str = "SLASTI_MORMANTI";

#[derive(Debug, Default)]
struct QemuFilesystemBytesHelper {
    pub bytes: Vec<u8>,
    pub cnt: usize,
}

impl<S> QemuHelper<S> for QemuFilesystemBytesHelper
where
    S: HasMetadata + UsesInput<Input = BytesInput>,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.syscalls_function(Self::hook_filesystem_syscalls::<QT, S>);
    }

    fn pre_exec(&mut self, _: &Emulator, input: &BytesInput) {
        let target = input.target_bytes();
        let buf = target.as_slice();
        self.bytes.clear();
        self.bytes.extend_from_slice(buf);
        self.cnt = 0;
    }
}

impl QemuFilesystemBytesHelper {
    fn hook_filesystem_syscalls<QT, S>(
        hooks: &mut QemuHooks<QT, S>,
        _state: Option<&mut S>,
        sys_num: i32,
        a0: u64,
        a1: u64,
        a2: u64,
        _a3: u64,
        _a4: u64,
        _a5: u64,
        _a6: u64,
        _a7: u64,
    ) -> SyscallHookResult
    where
        QT: QemuHelperTuple<S>,
        S: UsesInput<Input = BytesInput>,
    {
        let emu = hooks.emulator().clone();
        match sys_num as i64 {
            SYS_openat => {
                if a1 != 0 {
                    let cstr = unsafe { CStr::from_ptr(emu.g2h(a1)) };
                    if let Ok(pathname) = cstr.to_str() {
                        if pathname.contains(MAGIC_FILENAME) {
                            let h = hooks
                                .match_helper_mut::<QemuFilesystemBytesHelper>()
                                .unwrap();
                            h.cnt = 0;
                            return SyscallHookResult::new(Some(MAGIC_FD));
                        }
                    }
                }
            }
            SYS_close => {
                if a0 == MAGIC_FD {
                    return SyscallHookResult::new(Some(0));
                }
            }
            SYS_read => {
                if a0 == MAGIC_FD {
                    let h = hooks
                        .match_helper_mut::<QemuFilesystemBytesHelper>()
                        .unwrap();
                    if h.cnt >= h.bytes.len() {
                        return SyscallHookResult::new(Some(0));
                    }
                    let mut size = a2 as usize;
                    if size > h.bytes.len() - h.cnt {
                        size = h.bytes.len() - h.cnt;
                    }
                    unsafe {
                        ptr::copy_nonoverlapping(
                            (&h.bytes[h.cnt..]).as_ptr(),
                            emu.g2h::<u8>(a1),
                            size,
                        )
                    };
                    h.cnt += size;
                    return SyscallHookResult::new(Some(size as u64));
                }
            }
            SYS_write => {
                if a0 == 1 || a0 == 2 {
                    // Ignore stdout/err for perf
                    return SyscallHookResult::new(Some(a2 as u64));
                }
            }
            SYS_lseek => {
                if a0 == MAGIC_FD {
                    let h = hooks
                        .match_helper_mut::<QemuFilesystemBytesHelper>()
                        .unwrap();
                    match a2 as i32 {
                        libc::SEEK_SET => {
                            if a1 as usize > h.bytes.len() {
                                return SyscallHookResult::new(Some(-libc::ENXIO as u64));
                            }
                            h.cnt = a1 as usize;
                        }
                        libc::SEEK_CUR => {
                            if h.cnt + a1 as usize > h.bytes.len() {
                                return SyscallHookResult::new(Some(-libc::ENXIO as u64));
                            }
                            h.cnt += a1 as usize;
                        }
                        libc::SEEK_END => {
                            let cnt = (h.bytes.len() as i64 + a1 as i64) as usize;
                            if cnt > h.bytes.len() {
                                return SyscallHookResult::new(Some(-libc::ENXIO as u64));
                            }
                            h.cnt = cnt;
                        }
                        _ => return SyscallHookResult::new(Some(-libc::EINVAL as u64)),
                    }
                    return SyscallHookResult::new(Some(h.cnt as u64));
                }
            }
            SYS_faccessat => {
                if a1 != 0 {
                    let cstr = unsafe { CStr::from_ptr(emu.g2h(a1)) };
                    if let Ok(pathname) = cstr.to_str() {
                        if pathname.contains(MAGIC_FILENAME) {
                            return SyscallHookResult::new(Some(0));
                        } else if pathname == "/dev/pmsg0" || pathname == "/dev/socket/logdw" {
                            return SyscallHookResult::new(Some(-libc::ENOENT as u64));
                        }
                    }
                }
            }
            SYS_newfstatat => {
                if a1 != 0 && a2 != 0 {
                    let cstr = unsafe { CStr::from_ptr(emu.g2h(a1)) };
                    if let Ok(pathname) = cstr.to_str() {
                        if pathname.contains(MAGIC_FILENAME) {
                            let h = hooks
                                .match_helper_mut::<QemuFilesystemBytesHelper>()
                                .unwrap();
                            // Got with python's os.lstat
                            let stat = emu.g2h::<libc::stat>(a2);
                            let stat = unsafe { stat.as_mut().unwrap() };
                            stat.st_mode = 33204;
                            stat.st_ino = 39595576;
                            stat.st_dev = 2053;
                            stat.st_nlink = 1;
                            stat.st_uid = 1000;
                            stat.st_gid = 1000;
                            stat.st_size = h.bytes.len() as i64;
                            stat.st_atime = 1637330679;
                            stat.st_mtime = 1637226480;
                            stat.st_ctime = 1637226480;
                            return SyscallHookResult::new(Some(0));
                        }
                    }
                }
            }
            SYS_rt_sigprocmask => {
                return SyscallHookResult::new(Some(0));
            }
            _ => (),
        };
        SyscallHookResult::new(None)
    }
}

const HARNESS_NAME: &str = "harnessDecode";

pub fn main() {
    env_logger::init();

    // Hardcoded parameters
    let timeout = Duration::from_secs(4);
    let intial_dirs = [PathBuf::from(env::args().nth(1).unwrap())];
    let objective_dir = PathBuf::from("./crashes");
    let corpus_dir = PathBuf::from(PathBuf::from(env::args().nth(2).unwrap()));

    let arg = env::args().nth(3).unwrap_or("0".into());
    let cores = Cores::from_cmdline(&arg).ok();

    env::remove_var("LD_PRELOAD");
    env::remove_var("LD_LIBRARY_PATH");

    // Initialize QEMU
    let mut args = vec!["qemu".into(), "./harness".into(), MAGIC_FILENAME.into()];
    let mut env: Vec<(String, String)> = env::vars().collect();

    #[cfg(feature = "asan")]
    let (emu, asan) = init_with_asan(&mut args, &mut env).unwrap();
    #[cfg(not(feature = "asan"))]
    let emu = Emulator::new(&mut args, &mut env).unwrap();

    emu.force_dfl(); // Ignore target crash sig handlers

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let harness_ptr = elf
        .resolve_symbol(HARNESS_NAME, emu.load_addr())
        .expect(&format!("Symbol {} not found", HARNESS_NAME));
    println!("{} @ {:#x}", HARNESS_NAME, harness_ptr);

    if cores.is_none() {
        // Repro
        let repro = arg;

        #[cfg(feature = "asan")]
        let mut hooks = QemuHooks::reproducer(
            emu.clone(),
            tuple_list!(
                QemuCallTracerHelper::new(
                    QemuFilterList::None,
                    tuple_list!(FullBacktraceCollector::new())
                ),
                QemuAsanHelper::with_asan_report(asan, QemuFilterList::None, QemuAsanOptions::None),
            ),
        );

        #[cfg(not(feature = "asan"))]
        let mut hooks = QemuHooks::reproducer(emu.clone(), ());

        /*emu.set_breakpoint(harness_ptr);
        unsafe { emu.run() };

        println!("Break at {:#x}", emu.read_reg::<_, u64>(Regs::Pc).unwrap());

        emu.remove_breakpoint(harness_ptr);

        // Now that the libs are loaded, build the intrumentation filter
        let mut allow_list = vec![];
        for region in emu.mappings() {
            if let Some(path) = region.path() {
                if path.contains("imagecodec") || path.contains("harness") {
                    allow_list.push(region.start()..region.end());
                    println!("Instrument {:?} {:#x}-{:#x}", path, region.start(), region.end());
                }
            }
        }

        hooks.match_helper_mut::<QemuAsanHelper>().unwrap().update_filter(QemuFilterList::AllowList(allow_list.clone()), &emu);*/

        let input = BytesInput::from_file(repro).unwrap();

        let mut test_harness = |input: &BytesInput| {
            input.to_file(MAGIC_FILENAME).unwrap();
            unsafe { emu.run() };
            ExitKind::Ok
        };

        hooks.repro_run(&mut test_harness, &input);

        return;
    }
    let cores = cores.unwrap();

    // Break at the entry point after the loading process
    if let Some(entry) = elf.entry_point(emu.load_addr()) {
        emu.set_breakpoint(entry);
        unsafe { emu.run() };

        println!(
            "Entry break at {:#x}",
            emu.read_reg::<_, u64>(Regs::Pc).unwrap()
        );

        emu.remove_breakpoint(entry);
    }

    // Now that the libs are loaded, build the intrumentation filter
    let mut allow_list = vec![];
    for region in emu.mappings() {
        if let Some(path) = region.path() {
            if path.contains("imagecodec") || path.contains("harness") {
                allow_list.push(region.start()..region.end());
                println!(
                    "Instrument {:?} {:#x}-{:#x}",
                    path,
                    region.start(),
                    region.end()
                );
            }
        }
    }

    let harness_ptr = elf
        .resolve_symbol(HARNESS_NAME, emu.load_addr())
        .expect(&format!("Symbol {} not found", HARNESS_NAME));
    println!("{} @ {:#x}", HARNESS_NAME, harness_ptr);

    emu.set_breakpoint(harness_ptr);
    unsafe { emu.run() };

    println!("Break at {:#x}", emu.read_reg::<_, u64>(Regs::Pc).unwrap());

    // Get the return address
    let ret_addr: u64 = emu.read_reg(Regs::Lr).unwrap();
    println!("Return address = {:#x}", ret_addr);

    emu.remove_breakpoint(harness_ptr);
    emu.set_breakpoint(ret_addr);

    let saved_cpu_states: Vec<_> = (0..emu.num_cpus())
        .map(|i| emu.cpu_from_index(i).save_state())
        .collect();

    #[cfg(feature = "snapshot")]
    let mut snapshot_helper = {
        // Create the helper and take the snapshot here to share the pages between all the clients
        // thanks to the Laucher using fork()
        let mut h = QemuSnapshotHelper::new();
        h.use_accurate_unmapping();
        h.snapshot(&emu);
        Some(h)
    };
    #[cfg(feature = "asan")]
    let mut asan = Some(asan);

    let mut harness = |_input: &BytesInput| {
        #[cfg(not(feature = "filesystem"))]
        _input.to_file(MAGIC_FILENAME).unwrap();

        unsafe { emu.run() };

        for (i, s) in saved_cpu_states.iter().enumerate() {
            emu.cpu_from_index(i).restore_state(s);
        }

        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
        // Create an observation channel using the coverage map
        #[cfg(not(feature = "classic"))]
        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };
        #[cfg(feature = "classic")]
        let edges_observer = unsafe { HitcountsMapObserver::new(std_edges_map_observer("edges")) };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create an observation channel using cmplog map
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

        // New maximization map feedback linked to the edges observer and the feedback state
        //let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
        let map_feedback = AflMapFeedback::tracking(&edges_observer, true, false);

        // Calibration stage
        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new()); //, TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep a cache in memory for performance
                CachedOnDiskCorpus::new(corpus_dir.clone(), 1024).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());

        // Mutational stage with power scheduling
        let power = StdPowerMutationalStage::new(mutator);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(powersched::PowerSchedule::FAST),
        ));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        #[cfg(not(feature = "classic"))]
        let helpers = tuple_list!(QemuEdgeCoverageHelper::new(QemuFilterList::AllowList(
            allow_list.clone()
        )));

        #[cfg(feature = "classic")]
        let helpers = tuple_list!(QemuEdgeCoverageClassicHelper::new(
            QemuFilterList::AllowList(allow_list.clone())
        ));

        #[cfg(feature = "filesystem")]
        let helpers = helpers.append(QemuFilesystemBytesHelper::default());

        #[cfg(feature = "snapshot")]
        let helpers = helpers.append(snapshot_helper.take().unwrap());

        #[cfg(feature = "asan")]
        let helpers = helpers.append(QemuAsanHelper::new(
            asan.take().unwrap(),
            QemuFilterList::AllowList(allow_list.clone()),
            QemuAsanOptions::Snapshot,
        ));

        let helpers = helpers
            .append(QemuCmpLogHelper::new(QemuFilterList::AllowList(
                allow_list.clone(),
            )))
            .append(QemuCmpLogRoutinesHelper::new(QemuFilterList::AllowList(
                allow_list.clone(),
            )));

        let mut hooks = QemuHooks::new(emu.clone(), helpers);

        // Create a QEMU in-process executor
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Show the cmplog observer
        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &intial_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &intial_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        let tracing = ShadowTracingStage::new(&mut executor);

        // Setup a randomic Input2State stage
        let i2s = StdMutationalStage::new(I2SRandReplace::new());

        let mut stages = tuple_list!(calibration, tracing, i2s, power);

        //let mut stages = tuple_list!(calibration, power);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        //fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 200)?;

        //mgr.on_restart(&mut state)?;

        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The monitor reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{}", s));

    //Setup an Monitor with AFL-Style UI to display the stats
    //let ui = TuiUI::with_version(
    //    String::from("Libfuzzer For Libpng"),
    //    String::from("0.0.1"),
    //    false,
    //);
    //let monitor = TuiMonitor::new(ui);

    let broker_port = portpicker::pick_unused_port().expect("No ports free");
    println!("Picking the free port {}", broker_port);

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::AlwaysUnique)
        .monitor(monitor)
        //.stdout_file(Some("/dev/null"))
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
