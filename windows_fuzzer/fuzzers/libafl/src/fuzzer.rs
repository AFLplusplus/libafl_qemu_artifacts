//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
//!
use core::time::Duration;
use std::{env, fs, path::PathBuf, process};

use clap::Parser;
use libafl::observers::CanTrack;
use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::{MultiMonitor, OnDiskJSONMonitor},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{CalibrationStage, StdMutationalStage},
    state::StdState,
    Error,
};
use libafl_bolts::{
    core_affinity::{CoreId, Cores},
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::executor::stateful::StatefulQemuExecutor;
use libafl_qemu::executor::QemuExecutorState;
use libafl_qemu::{
    edges::QemuEdgeCoverageClassicHelper, emu::Emulator, EmuExitReasonError, FastSnapshotManager,
    HandlerError, HandlerResult, QemuHooks, QemuInstrumentationAddressRangeFilter,
    QemuInstrumentationPagingFilter, QemuSnapshotManager, SnapshotManager, StdEmuExitHandler,
};
use libafl_targets::std_edges_map_observer;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    version,
    about,
    long_about = "QEMU systemmode fuzzer using sync exit instead of breakpoints."
)]
struct Cli {
    /// Copy the given file into a new file, specific to the fuzzing unit.
    /// Each occurrence of the old file in the command line is replaced with the newly copied file.
    #[arg(short, long)]
    multiplex_files: Option<Vec<PathBuf>>,
    /// Use Syx snapshots (a.k.a. Fast snapshots)
    #[arg(short, long)]
    syx_snapshot: bool,
    /// Use JIT'ed edge coverage feedback
    #[arg(short, long)]
    jit: bool,
    /// QEMU's command line to use for each QEMU process.
    #[arg(long)]
    qemu_args: String,
    /// Cores to run on.
    #[arg(short, long)]
    cores: Option<String>,
    /// Initial corpus directory
    #[arg(long)]
    initial_corpus_dir: PathBuf,
    /// Generated corpus directory
    #[arg(long)]
    generated_corpus_dir: PathBuf,
    /// Objective directory
    #[arg(long)]
    crashes_dir: PathBuf,
    /// On-disk result
    #[arg(long)]
    result_output: Option<PathBuf>,
}

pub fn fuzz() {
    env_logger::init();
    let cli = Cli::parse();
    let qemu_args_end: Vec<String> = cli
        .qemu_args
        .clone()
        .split_whitespace()
        .map(|s| s.into())
        .collect();
    let mut qemu_args: Vec<String> = vec![env::args().next().unwrap().clone()];
    qemu_args.extend(qemu_args_end);

    assert!(cli.initial_corpus_dir.is_dir());
    assert!(cli.generated_corpus_dir.is_dir());
    assert!(cli.crashes_dir.is_dir());

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };
    // Hardcoded parameters
    let timeout = Duration::from_secs(10);
    let broker_port = 1337;

    let cores_str = if let Some(cores_s) = &cli.cores {
        cores_s.clone()
    } else {
        "1".to_string()
    };

    let cores = Cores::from_cmdline(cores_str.as_str()).unwrap();
    let corpus_dirs = [cli.initial_corpus_dir.clone()];
    let objective_dir = cli.crashes_dir.clone();

    println!(
        "QEMU systemmode Fuzzer - {} - {} - Cores {:?}",
        if cli.syx_snapshot {
            "Syx Snapshot"
        } else {
            "Normal Snapshot"
        }, // Syx vs Normal snapshot
        if cli.jit {
            "JIT feedback"
        } else {
            "Normal feedback"
        }, // JIT vs Normal feedback
        cores.ids
    );

    let mut run_client = |state: Option<_>, mut mgr, core_id: CoreId| {
        // Multiplex files
        if let Some(multiplex_files) = &cli.multiplex_files {
            for file in multiplex_files {
                let mut new_file_path = file.clone();
                if let Some(old_extension) = file.extension() {
                    let new_extension =
                        format!("{}.{}", old_extension.to_str().unwrap(), core_id.0);
                    new_file_path.set_extension(new_extension);
                } else {
                    new_file_path.set_extension(format!("{}", core_id.0));
                }

                // To avoid accidents...
                assert_ne!(file.as_os_str(), new_file_path.as_os_str());

                println!("Copying {:?} to {:?}...", file, new_file_path);
                fs::copy(file, &new_file_path).unwrap();

                for arg in &mut qemu_args {
                    *arg = arg.replace(
                        file.file_name().unwrap().to_str().unwrap(),
                        new_file_path.file_name().unwrap().to_str().unwrap(),
                    );
                }
            }
        }

        // Initialize QEMU
        let env: Vec<(String, String)> = env::vars().collect();
        let emu_snapshot_manager: SnapshotManager = if cli.syx_snapshot {
            SnapshotManager::Fast(FastSnapshotManager::new(false))
        } else {
            SnapshotManager::Qemu(QemuSnapshotManager::new(true))
        };
        let emu_exit_handler: StdEmuExitHandler<SnapshotManager> =
            StdEmuExitHandler::new(emu_snapshot_manager);
        let emu = Emulator::new(&qemu_args, &env, emu_exit_handler).unwrap();

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness =
            |input: &BytesInput, qemu_executor_state: &mut QemuExecutorState<_, _>| unsafe {
                match emu.run(input, qemu_executor_state) {
                    Ok(handler_result) => match handler_result {
                        HandlerResult::UnhandledExit(unhandled_exit) => {
                            panic!("Unhandled exit: {}", unhandled_exit)
                        }
                        HandlerResult::EndOfRun(exit_kind) => exit_kind,
                        HandlerResult::Interrupted => {
                            println!("Interrupted.");
                            std::process::exit(0);
                        }
                    },
                    Err(handler_error) => match handler_error {
                        HandlerError::QemuExitReasonError(emu_exit_reason_error) => {
                            match emu_exit_reason_error {
                                EmuExitReasonError::UnknownKind => panic!("unknown kind"),
                                EmuExitReasonError::UnexpectedExit => ExitKind::Crash,
                                _ => {
                                    panic!("Emu Exit unhandled error: {:?}", emu_exit_reason_error)
                                }
                            }
                        }
                        _ => panic!("Unhandled error: {:?}", handler_error),
                    },
                }
            };

        // Create an observation channel using the coverage map
        let edges_observer =
            unsafe { HitcountsMapObserver::new(std_edges_map_observer("edges")).track_indices() };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryOnDiskCorpus::new(cli.generated_corpus_dir.clone()).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // Setup a havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            CalibrationStage::new(&calibration_feedback),
            StdMutationalStage::new(mutator),
        );

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut hooks = QemuHooks::new(
            *emu.qemu(),
            tuple_list!(QemuEdgeCoverageClassicHelper::new(
                QemuInstrumentationAddressRangeFilter::None,
                QemuInstrumentationPagingFilter::None,
                cli.jit
            )),
        );

        // Create a QEMU in-process executor
        let mut executor = StatefulQemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            // println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!(" {}", s));

    if let Some(on_disk_result) = cli.result_output {
        let monitor_on_disk = OnDiskJSONMonitor::new(on_disk_result, monitor, |_| true);

        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .run_client(&mut run_client)
            // .stdout_file(Some("/dev/null"))
            .cores(&cores)
            .monitor(monitor_on_disk)
            .build()
            .launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
            Err(err) => panic!("Failed to run launcher: {err:?}"),
        }
    } else {
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .run_client(&mut run_client)
            // .stdout_file(Some("/dev/null"))
            .cores(&cores)
            .monitor(monitor)
            .build()
            .launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
            Err(err) => panic!("Failed to run launcher: {err:?}"),
        }
    }
}
