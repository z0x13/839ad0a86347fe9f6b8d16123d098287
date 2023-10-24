use clap::builder::ArgPredicate;
use clap::{Arg, ArgMatches, Command};
use std::path::PathBuf;

use crate::template::{
    Antidebug, CustomAntidebug, DebugActions, DebugDetection, Encryption, Execution, Format, Level,
    Obfuscation, Sandbox, SandboxDetection, Template, Vm, VmDetection,
};
use crate::utils::absolute_path;
use crate::utils::styles::get_styles;
use crate::virustotal::VirusTotal;

fn parser() -> ArgMatches {
    Command::new("Tool")
        .help_template(
"{before-help}
{about}
Coded by {author-with-newline}
{all-args}
{after-help}"
)
        .author("\x1b[32mz0x")
        .styles(get_styles())
        .about("Tool for injectors generation based on templates")
        .arg_required_else_help(true)
        .arg(
            Arg::new("path to shellcode file")
                .short('f')
                .long("shellcode")
                .required(true),
        )
        .arg(
            Arg::new("binary output format")
                .short('b')
                .long("format")
                .required(false)
                .default_value("exe")
                .value_parser([
                    clap::builder::PossibleValue::new("exe"),
                    clap::builder::PossibleValue::new("dll"),
                ]),
        )
        .arg(
            Arg::new("execution technique")
                .short('i')
                .long("technique")
                .required(false)
                .default_value("ntapc")
                .value_parser([
                    clap::builder::PossibleValue::new("ntapc")
                        .help("Self inject using APC low level APIs"),
                    clap::builder::PossibleValue::new("create-process")
                        .help("Self inject using CreateProcessA and indirect memory modification"),
                    clap::builder::PossibleValue::new("etwp")
                        .help("Self inject using EtwpCreateEtwThread"),
                    clap::builder::PossibleValue::new("make_exec")
                        .help("Self inject using make_exec function from memmap2 crate"),
                    clap::builder::PossibleValue::new("fiber")
                        .help("Self inject using ConvertThreadToFiber and CreateFiber"),
                    clap::builder::PossibleValue::new("ntcrt")
                        .help("Create Remote Thread using low level APIs"),
                    clap::builder::PossibleValue::new("syscrt")
                        .help("Create Remote Thread using syscalls"),
                    clap::builder::PossibleValue::new("wincrt")
                        .help("Create Remote Thread using the official Windows Crate"),
                    clap::builder::PossibleValue::new("module-stomping")
                        .help("Sophiscated Remote inject"),
                    clap::builder::PossibleValue::new("test")
                        .help("Local inject (unstable)"),
                ]),
        )
        .arg(
            Arg::new("target process")
                .short('t')
                .long("target")
                .required(false)
                .default_value("dllhost.exe")
                .help("Target processes to inject into. Case sensitive!"),
        )
        .arg(
            Arg::new("encryption method")
                .short('e')
                .long("encryption")
                .required(false)
                .help(
                    "The shellcode is encrypted and placed in a binary file along with a decryption function. \n\
                    It will be decrypted during execution",
                )
                .value_parser([
                    clap::builder::PossibleValue::new("xor").help("Xor key length = 1 byte"),
                    clap::builder::PossibleValue::new("smart-xor")
                        .help("Xor key length is equal to shellcode length"),
                    clap::builder::PossibleValue::new("aes")
                        .help("AES-256 CBC mode (key = 32 bytes, iv = 16 bytes) encryption"),
                    clap::builder::PossibleValue::new("chacha20")
                        .help("ChaCha20poly1305 (key = 32 bytes, nonce = 12 bytes) encryption"),
                    clap::builder::PossibleValue::new("rc4")
                        .help("RC4 (key = 32 bytes) encryption"),
                    clap::builder::PossibleValue::new("rabbit")
                        .help("Rabbit (key = 16 bytes, nonce = 8 bytes) encryption"),
                ]),
        )
        .arg(
            Arg::new("obfuscation method")
                .short('o')
                .long("obfuscation")
                .required(false)
                .help(
                    "The shellcode is obfuscated and placed in a binary file along with a deobfusaction function. \n\
                    It will be deobfuscated during execution",
                )
                .long_help(
                    r"The shellcode is obfuscated and placed in a binary file along with a deobfusaction function.
It will be deobfuscated during execution.

See obfuscation results for shellcode:
\x8B\xEC\x33\xFF\x57\xC6\x45\xFC
\x63\xC6\x45\xFD\x6D\xC6\x45\xFE"
                )
                .value_parser([
                    clap::builder::PossibleValue::new("ipv4")
                        .help("139.236.51.255, 87.198.69.252, 99.198.69.253, 109.198.69.254"),
                    clap::builder::PossibleValue::new("ipv6")
                        .help("8bec:33ff:57c6:45fc:63c6:45fd:6dc6:45fe"),
                    clap::builder::PossibleValue::new("mac-addr")
                        .help("8b:ec:33:ff:57:c6, 45:fc:63:c6:45:fd, 6d:c6:45:fe"),
                    clap::builder::PossibleValue::new("base32")
                        .help("RPWDH72XYZC7YY6GIX6W3RSF7Y======"),
                    clap::builder::PossibleValue::new("base45")
                        .help("0VH P6F4B6%8RRC7%8M*D8%8"),
                    clap::builder::PossibleValue::new("base58")
                        .help("JH92T4eLgiTnu2YvCTMwTb"),
                    clap::builder::PossibleValue::new("base62")
                        .help("aJKKzixdWmSvbr1iVgu53C"),
                    clap::builder::PossibleValue::new("base64")
                        .help("i+wz/1fGRfxjxkX9bcZF/g=="),
                    clap::builder::PossibleValue::new("base85")
                        .help("i|jN1SH?yBW5z}OZN^3Z"),
                ]),
        )
        .arg(
            Arg::new("debugging detection")
                .long("antidebug")
                .required(false)
                .conflicts_with("debugging detection presets")
                .num_args(1..=9)
                .value_parser([
                    clap::builder::PossibleValue::new("PebIsDebuggerPresent")
                        .help("PEB parsing: BeingDebugged flag"),
                    clap::builder::PossibleValue::new("PebNTGlobalFlag")
                        .help("PEB parsing: NT Global flag (FLG_HEAP_VALIDATE_PARAMETERS, FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK)"),
                    clap::builder::PossibleValue::new("PebHeapFlags")
                        .help("PEB parsing: struct _HEAP (field Flags and ForceFlags)"),
                    clap::builder::PossibleValue::new("IsDebuggerPresent")
                        .help("WINAPI: IsDebuggerPresent() function"),
                    clap::builder::PossibleValue::new("CheckRemoteDebuggerPresent")
                        .help("WINAPI: CheckRemoteDebuggerPresent() function"),
                    clap::builder::PossibleValue::new("NTQueryDebugPort")
                        .help("WINAPI: NtQueryInformationProcess() fucntion - check ProcessDbgPort"),
                    clap::builder::PossibleValue::new("NTQueryDebugObject")
                        .help("WINAPI: NtQueryInformationProcess() fucntion - check DebugObject"),
                    clap::builder::PossibleValue::new("NTQueryDebugFlags")
                        .help("WINAPI: NtQueryInformationProcess() fucntion - check ProcessDebugFlags"),
                    clap::builder::PossibleValue::new("DebugRegisters")
                        .help("Check debug registers (D0 - D4)"),
                ]),
        )
        .arg(
            Arg::new("antidebug action")
                .long("antidebug-action")
                .required(false)
                .conflicts_with("debugging detection presets")
                .requires("debugging detection")
                .default_value_if("debugging detection", ArgPredicate::IsPresent, "hide")
                .num_args(1)
                .help("Action if debugger detected")
                .value_parser([
                    clap::builder::PossibleValue::new("hide")
                        .help("NtCreateThreadEx (CreateFlags: THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)"),
                    clap::builder::PossibleValue::new("exit")
                        .help("End the process"),
                ]),
        )
        .arg(
            Arg::new("debugging detection presets")
                .long("antidebug-preset")
                .required(false)
                .default_missing_value("basic")
                .conflicts_with("debugging detection")
                .num_args(0..=1)
                .value_parser([
                    clap::builder::PossibleValue::new("low")
                        .help(
                            "IsDebuggerPresent() -> exit",
                        ),
                    clap::builder::PossibleValue::new("basic")
                        .help(
                            "BeingDebugged flag + NT Global flag -> hide",
                        ),
                    clap::builder::PossibleValue::new("paranoid")
                        .help(
                            "BeingDebugged flag + NT Global flag + CheckRemoteDebuggerPresent() + DebugRegisters -> exit",
                        ),
                ]),
        )
        .arg(
            Arg::new("sandbox detection")
                .long("sandbox")
                .required(false)
                .conflicts_with("sandbox detection presets")
                .num_args(1..=3)
                .help("End the process if running inside a sandbox")
                .value_parser([
                    clap::builder::PossibleValue::new("sbiedll")
                        .help("Check for sbiedll.dll"),
                    clap::builder::PossibleValue::new("input-time")
                        .help("Check input delay"),
                    clap::builder::PossibleValue::new("cursor")
                        .help("Check cursor movement"),
                ]),
        )
        .arg(
            Arg::new("sandbox detection presets")
                .long("sandbox-preset")
                .required(false)
                .default_missing_value("basic")
                .conflicts_with("sandbox detection")
                .num_args(0..=1)
                .value_parser([
                    clap::builder::PossibleValue::new("low")
                        .help("sbiedll -> exit"),
                    clap::builder::PossibleValue::new("basic")
                        .help("sbiedll -> exit"),
                    clap::builder::PossibleValue::new("paranoid")
                        .help(
                            "sbiedll + input-time + cursor -> exit",
                        )
                ]),
        )
        .arg(
            Arg::new("virtual machine detection")
                .long("vm")
                .required(false)
                .conflicts_with("virtual machine detection presets")
                .num_args(1..=4)
                .help("End the process if running inside a virtual machine")
                .value_parser([
                    clap::builder::PossibleValue::new("cpuid-hw")
                        .help("Cpuid - check if hypervisor bit present"),
                    clap::builder::PossibleValue::new("cpuid-vendor").
                        help("Cpuid - check hypervisor vendor.  \n\
                        Since for Hyper-V virtual machines the hypervisor bit \n\
                    is present even on the host machine, \n\
                    if the vendor id is equal to 'Microsoft Hv', \n\
                    the program will assume that this is not a virtual machine"),
                    clap::builder::PossibleValue::new("rdtsc")
                        .help("Check time delay"),
                    clap::builder::PossibleValue::new("rdtsc-vmexit")
                        .help("Check virtual machine exit time delay"),
                ]),
        )
        .arg(
            Arg::new("virtual machine detection presets")
                .long("vm-preset")
                .required(false)
                .default_missing_value("basic")
                .conflicts_with("virtual machine detection")
                .num_args(0..=1)
                .value_parser([
                    clap::builder::PossibleValue::new("low")
                        .help("Cpuid-HW -> exit (Hyper-V FP, see cpuid hypervisor vendor description)"),
                    clap::builder::PossibleValue::new("basic")
                        .help("Cpuid-Vendor -> exit"),
                    clap::builder::PossibleValue::new("paranoid")
                        .help("Cpuid-Vendor + RDTSC + RDTSC vmexit -> exit"),
                ]),
        )
        .arg(
            Arg::new("self destroy")
                .long("self-destroy")
                .required(false)
                .default_value("false")
                .num_args(0)
                .help("Immediately after the program is loaded into memory, \n\
                injector will delete its own executable file"),
        )
        .arg(
            Arg::new("debug privilege")
                .long("debug-privilege")
                .required(false)
                .default_value("false")
                .num_args(0)
                .help("Enable debug privilege for process. Required for <not implemented yet>"),
        )
        .arg(
            Arg::new("virus total check")
                .long("virustotal")
                .required(false)
                .requires("virus total api key")
                .default_value("false")
                .num_args(0)
                .help("Send generated binary to VirusTotal, display detections"),
        )
        .arg(
            Arg::new("antivirus bypass")
                .long("bypass")
                .required(false)
                .requires("virus total api key")
                .conflicts_with_all(["encryption method", "obfuscation method", "virus total check"])
                .num_args(1)
                .help("Generate an injector that will not be detected by a specific antivirus.\n\
                 All possible encryption and obfuscation algorithms are tried, \n\
                  and the compiled template is checked using VirusTotal. \n\
                  If the injector is not detected by the selected antivirus, the generation stops")
                .value_parser([
                    "Bkav",
                    "TrendMicro",
                    "Rising",
                    "Cybereason",
                    "Trapmine",
                    "TACHYON",
                    "NANO-Antivirus",
                    "Avast",
                    "FireEye",
                    "Zoner",
                    "AhnLab-V3",
                    "Fortinet",
                    "AVG",
                    "CMC",
                    "K7GW",
                    "Panda",
                    "Malwarebytes",
                    "GData",
                    "VBA32",
                    "Gridinsoft",
                    "Antiy-AVL",
                    "Sangfor",
                    "tehtris",
                    "ViRobot",
                    "ZoneAlarm",
                    "K7AntiVirus",
                    "Baidu",
                    "Kingsoft",
                    "APEX",
                    "Tencent",
                    "Sophos",
                    "Ikarus",
                    "Jiangmin",
                    "MaxSecure",
                    "Avira",
                    "CAT-QuickHeal",
                    "Cylance",
                    "VirIT",
                    "Yandex",
                    "Kaspersky",
                    "TrendMicro-HouseCall",
                    "DeepInstinct",
                    "VIPRE",
                    "MicroWorld-eScan",
                    "Varist",
                    "Zillya",
                    "BitDefender",
                    "Acronis",
                    "Emsisoft",
                    "SUPERAntiSpyware",
                    "Lionic",
                    "ClamAV",
                    "Paloalto",
                    "Alibaba",
                    "Skyhigh",
                    "DrWeb",
                    "Elastic",
                    "Microsoft",
                    "McAfee",
                    "CrowdStrike",
                    "Symantec",
                    "Xcitium",
                    "Webroot",
                    "Arcabit",
                    "ESET-NOD32",
                    "MAX",
                    "ALYac",
                    "SentinelOne",
                    "Cynet",
                    "BitDefenderTheta",
                    "F-Secure"
                ])
        )
        .arg(
            Arg::new("virus total api key")
                .long("api-key")
                .required(false)
                .num_args(1)
                .help("Required for --virustotal and --bypass options")
        )
        .get_matches()
}

fn args_checker(args: ArgMatches) -> Result<(Template, VirusTotal), Box<dyn std::error::Error>> {
    let sp: String = args
        .get_one::<String>("path to shellcode file")
        .unwrap()
        .clone();
    let relative_shellcode_path: PathBuf = [sp].iter().collect();
    let shellcode_path = match absolute_path(relative_shellcode_path) {
        Ok(path) => path,
        Err(err) => panic!("{:?}", err),
    };

    let encryption: Option<Encryption> = match args.get_one::<String>("encryption method") {
        Some(content) => match content.as_str() {
            "xor" => Some(Encryption::Xor),
            "smart-xor" => Some(Encryption::SmartXor),
            "aes" => Some(Encryption::Aes),
            "chacha20" => Some(Encryption::ChaCha20),
            "rc4" => Some(Encryption::RC4),
            "rabbit" => Some(Encryption::Rabbit),
            _ => panic!("Don't even know how this error exists."),
        },
        _ => None,
    };

    let obfuscation: Option<Obfuscation> = match args.get_one::<String>("obfuscation method") {
        Some(content) => match content.as_str() {
            "ipv4" => Some(Obfuscation::Ipv4),
            "ipv6" => Some(Obfuscation::Ipv6),
            "base32" => Some(Obfuscation::Base32),
            "base45" => Some(Obfuscation::Base45),
            "base58" => Some(Obfuscation::Base58),
            "base62" => Some(Obfuscation::Base62),
            "base64" => Some(Obfuscation::Base64),
            "base85" => Some(Obfuscation::Base85),
            "mac-addr" => Some(Obfuscation::MacAddr),
            _ => panic!("Don't even know how this error exists."),
        },
        _ => None,
    };

    let s = args.get_one::<String>("execution technique").unwrap();
    let execution: Execution = match s.as_str() {
        "ntapc" => Execution::NtQueueUserAPC,
        "ntcrt" => Execution::NtCreateRemoteThread,
        "syscrt" => Execution::SysCreateRemoteThread,
        "wincrt" => Execution::WinCreateRemoteThread,
        "make_exec" => Execution::MakeExec,
        "etwp" => Execution::Etwp,
        "fiber" => Execution::CreateFiber,
        "module-stomping" => Execution::ModuleStomping,
        "create-process" => Execution::CreateProcess,
        "test" => Execution::Test,
        _ => panic!("Don't even know how this error exists."),
    };

    let antidebug_preset: Option<Level> =
        match args.get_one::<String>("debugging detection presets") {
            Some(content) => match content.as_str() {
                "low" => Some(Level::Low),
                "basic" => Some(Level::Basic),
                "paranoid" => Some(Level::Paranoid),
                _ => panic!("Don't even know how this error exists."),
            },
            _ => None,
        };

    let custom_antidebug_strings = args
        .get_many::<String>("debugging detection")
        .map(|content| content.map(|s| s.as_str()));

    let mut custom_antidebug_opts: Vec<DebugDetection> = Vec::new();
    if custom_antidebug_strings.iter().len() != 0 {
        for technique in custom_antidebug_strings.unwrap() {
            match technique {
                "IsDebuggerPresent" => {
                    custom_antidebug_opts.push(DebugDetection::IsDebuggerPresent)
                }
                "PebIsDebuggerPresent" => {
                    custom_antidebug_opts.push(DebugDetection::PebIsDebuggerPresent)
                }
                "PebNTGlobalFlag" => custom_antidebug_opts.push(DebugDetection::PebNTGlobalFlag),
                "PebHeapFlags" => custom_antidebug_opts.push(DebugDetection::PebHeapFlags),
                "CheckRemoteDebuggerPresent" => {
                    custom_antidebug_opts.push(DebugDetection::CheckRemoteDebuggerPresent)
                }
                "NTQueryDebugPort" => custom_antidebug_opts.push(DebugDetection::NTQueryDebugPort),
                "NTQueryDebugObject" => {
                    custom_antidebug_opts.push(DebugDetection::NTQueryDebugObject)
                }
                "NTQueryDebugFlags" => {
                    custom_antidebug_opts.push(DebugDetection::NTQueryDebugFlags)
                }
                "DebugRegisters" => custom_antidebug_opts.push(DebugDetection::DebugRegisters),
                _ => panic!("Don't even know how this error exists."),
            };
        }
    }
    let custom_antidebug_action: Option<DebugActions> =
        match args.get_one::<String>("antidebug action") {
            Some(content) => match content.as_str() {
                "hide" => Some(DebugActions::Hide),
                "exit" => Some(DebugActions::Exit),
                _ => panic!("Don't even know how this error exists."),
            },
            _ => None,
        };
    let antidebug: Option<Antidebug> = match custom_antidebug_opts.len() {
        0 => antidebug_preset.map(|level| Antidebug {
            custom: None,
            preset: Some(level),
        }),
        _ => custom_antidebug_action.map(|action| Antidebug {
            custom: Some(CustomAntidebug {
                detection_methods: custom_antidebug_opts,
                action,
            }),
            preset: None,
        }),
    };

    let vm_preset: Option<Level> = match args.get_one::<String>("virtual machine detection presets")
    {
        Some(content) => match content.as_str() {
            "low" => Some(Level::Low),
            "basic" => Some(Level::Basic),
            "paranoid" => Some(Level::Paranoid),
            _ => panic!("Don't even know how this error exists."),
        },
        _ => None,
    };
    let custom_vm_strings = args
        .get_many::<String>("virtual machine detection")
        .map(|content| content.map(|s| s.as_str()));
    let mut custom_vm_opts: Vec<VmDetection> = Vec::new();
    if custom_vm_strings.iter().len() != 0 {
        for technique in custom_vm_strings.unwrap() {
            match technique {
                "cpuid-hw" => custom_vm_opts.push(VmDetection::CpuidHWbit),
                "cpuid-vendor" => custom_vm_opts.push(VmDetection::CpuidVmVendor),
                "rdtsc" => custom_vm_opts.push(VmDetection::Rdtsc),
                "rdtsc-vmexit" => custom_vm_opts.push(VmDetection::RdtscVmExit),
                _ => panic!("Don't even know how this error exists."),
            };
        }
    }
    let vm: Option<Vm> = match custom_vm_opts.len() {
        0 => vm_preset.map(|level| Vm {
            custom: None,
            preset: Some(level),
        }),
        _ => Some(Vm {
            custom: Some(custom_vm_opts),
            preset: None,
        }),
    };

    let sandbox_preset: Option<Level> = match args.get_one::<String>("sandbox detection presets") {
        Some(content) => match content.as_str() {
            "low" => Some(Level::Low),
            "basic" => Some(Level::Basic),
            "paranoid" => Some(Level::Paranoid),
            _ => panic!("Don't even know how this error exists."),
        },
        _ => None,
    };
    let custom_sandbox_strings = args
        .get_many::<String>("sandbox detection")
        .map(|content| content.map(|s| s.as_str()));
    let mut custom_sandbox_opts: Vec<SandboxDetection> = Vec::new();
    if custom_sandbox_strings.iter().len() != 0 {
        for technique in custom_sandbox_strings.unwrap() {
            match technique {
                "sbiedll" => custom_sandbox_opts.push(SandboxDetection::Sbiedll),
                "cursor" => custom_sandbox_opts.push(SandboxDetection::CursorPosition),
                "input-time" => custom_sandbox_opts.push(SandboxDetection::InputTime),
                _ => panic!("Don't even know how this error exists."),
            };
        }
    }
    let sandbox: Option<Sandbox> = match custom_sandbox_opts.len() {
        0 => sandbox_preset.map(|level| Sandbox {
            custom: None,
            preset: Some(level),
        }),
        _ => Some(Sandbox {
            custom: Some(custom_sandbox_opts),
            preset: None,
        }),
    };

    let s = args.get_one::<String>("binary output format").unwrap();
    let format: Format = match s.as_str() {
        "exe" => Format::Exe,
        "dll" => Format::Dll,
        _ => panic!("Don't even know how this error exists."),
    };

    let target_process = args
        .get_one::<String>("target process")
        .unwrap()
        .to_string();

    let self_destroy = matches!(args.get_one::<bool>("self destroy"), Some(true));
    let debug_privilege = matches!(args.get_one::<bool>("debug privilege"), Some(true));

    let virustotal_enabled = matches!(args.get_one::<bool>("virus total check"), Some(true));
    let bypass_target = args
        .get_one::<String>("antivirus bypass")
        .map(|content| content.to_owned());
    let virustotal: VirusTotal = match args.get_one::<String>("virus total api key") {
        Some(content) => VirusTotal {
            api_key: Some(content.to_owned()),
            bypass_target,
            is_enabled: virustotal_enabled,
        },
        _ => VirusTotal {
            api_key: None,
            bypass_target,
            is_enabled: virustotal_enabled,
        },
    };

    let template = Template {
        project_path: None,
        shellcode_path,
        execution,
        encryption,
        obfuscation,
        format,
        target_process,
        antidebug,
        sandbox,
        vm,
        self_destroy,
        debug_privilege,
    };

    Ok((template, virustotal))
}

pub fn meta_arg_parser() -> (Template, VirusTotal) {
    let args = parser();
    match args_checker(args) {
        Ok(content) => content,
        Err(err) => panic!("{:?}", err),
    }
}
