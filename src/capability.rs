//! Capabilities and severities.
//!
//! A capability is the thing a host grants, not the function that grants it.
//! Several imports usually map onto one capability — `fd_read`, `fd_write`
//! and `path_open` are all "filesystem" — and it is the union across the
//! import list that describes what the module can do. Reporting the union is
//! the point: `path_open` on its own is a file reader, and `path_open`
//! together with `sock_send` is an exfiltration path.

use std::fmt;

/// How confident the classification is about *why* it fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Basis {
    /// The import name is part of an interface this tool models explicitly
    /// from that interface's own definition.
    Documented,
    /// The import name matched a naming pattern rather than a known
    /// interface. Useful, and reported as a guess.
    Pattern,
}

impl Basis {
    /// Short tag used in reports.
    pub fn tag(self) -> &'static str {
        match self {
            Basis::Documented => "documented",
            Basis::Pattern => "pattern",
        }
    }
}

/// Finding severity. Ordered so that reports can sort and policies can
/// threshold on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// All severities, lowest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Lower-case name, as used on the command line and in JSON.
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity name.
    pub fn parse(s: &str) -> Option<Severity> {
        Severity::ALL
            .iter()
            .copied()
            .find(|sev| sev.name() == s.to_ascii_lowercase())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a host grants a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Filesystem,
    Network,
    HostIo,
    Process,
    Clock,
    Randomness,
    Environment,
    Polling,
    Threads,
    RawSyscall,
    IndirectJsDispatch,
    JsArbitrary,
    JsEval,
    JsNetwork,
    JsStorage,
    JsMessaging,
    JsCrypto,
    JsDom,
    ContractStorageRead,
    ContractStorageWrite,
    ContractCall,
    ContractDelegateCall,
    ContractValueTransfer,
    ContractCodeDeploy,
    ContractSelfDestruct,
    ContractRandomness,
    ContractChainContext,
    ContractCrypto,
    ContractAccountKeys,
    HostMemory,
    HostTable,
    HostMutableGlobal,
    HostTag,
    DebugLogging,
    Unknown,
}

impl Capability {
    /// Every capability, in the order reports list them.
    pub const ALL: [Capability; 35] = [
        Capability::Filesystem,
        Capability::Network,
        Capability::HostIo,
        Capability::Process,
        Capability::Clock,
        Capability::Randomness,
        Capability::Environment,
        Capability::Polling,
        Capability::Threads,
        Capability::RawSyscall,
        Capability::IndirectJsDispatch,
        Capability::JsArbitrary,
        Capability::JsEval,
        Capability::JsNetwork,
        Capability::JsStorage,
        Capability::JsMessaging,
        Capability::JsCrypto,
        Capability::JsDom,
        Capability::ContractStorageRead,
        Capability::ContractStorageWrite,
        Capability::ContractCall,
        Capability::ContractDelegateCall,
        Capability::ContractValueTransfer,
        Capability::ContractCodeDeploy,
        Capability::ContractSelfDestruct,
        Capability::ContractRandomness,
        Capability::ContractChainContext,
        Capability::ContractCrypto,
        Capability::ContractAccountKeys,
        Capability::HostMemory,
        Capability::HostTable,
        Capability::HostMutableGlobal,
        Capability::HostTag,
        Capability::DebugLogging,
        Capability::Unknown,
    ];

    /// The stable identifier used in policy files and JSON output.
    pub fn id(self) -> &'static str {
        match self {
            Capability::Filesystem => "filesystem",
            Capability::Network => "network",
            Capability::HostIo => "host-io",
            Capability::Process => "process",
            Capability::Clock => "clock",
            Capability::Randomness => "randomness",
            Capability::Environment => "environment",
            Capability::Polling => "polling",
            Capability::Threads => "threads",
            Capability::RawSyscall => "raw-syscall",
            Capability::IndirectJsDispatch => "indirect-js-dispatch",
            Capability::JsArbitrary => "js-arbitrary",
            Capability::JsEval => "js-eval",
            Capability::JsNetwork => "js-network",
            Capability::JsStorage => "js-storage",
            Capability::JsMessaging => "js-messaging",
            Capability::JsCrypto => "js-crypto",
            Capability::JsDom => "js-dom",
            Capability::ContractStorageRead => "contract-storage-read",
            Capability::ContractStorageWrite => "contract-storage-write",
            Capability::ContractCall => "contract-call",
            Capability::ContractDelegateCall => "contract-delegate-call",
            Capability::ContractValueTransfer => "contract-value-transfer",
            Capability::ContractCodeDeploy => "contract-code-deploy",
            Capability::ContractSelfDestruct => "contract-self-destruct",
            Capability::ContractRandomness => "contract-randomness",
            Capability::ContractChainContext => "contract-chain-context",
            Capability::ContractCrypto => "contract-crypto",
            Capability::ContractAccountKeys => "contract-account-keys",
            Capability::HostMemory => "host-memory",
            Capability::HostTable => "host-table",
            Capability::HostMutableGlobal => "host-mutable-global",
            Capability::HostTag => "host-tag",
            Capability::DebugLogging => "debug-logging",
            Capability::Unknown => "unknown",
        }
    }

    /// One line on what the capability actually grants.
    pub fn describes(self) -> &'static str {
        match self {
            Capability::Filesystem => {
                "read and write host files, within whatever the host preopened"
            }
            Capability::Network => "open, read and write network sockets",
            Capability::HostIo => "read and write host-provided byte streams",
            Capability::Process => "end or signal the process it runs in",
            Capability::Clock => "read host clocks",
            Capability::Randomness => "draw bytes from the host's entropy source",
            Capability::Environment => "read environment variables and argv",
            Capability::Polling => "wait on host events",
            Capability::Threads => "share memory with, or park on, other instances",
            Capability::RawSyscall => "issue raw kernel syscalls through the host shim",
            Capability::IndirectJsDispatch => "call host function-table entries chosen at run time",
            Capability::JsArbitrary => "call into host JavaScript",
            Capability::JsEval => "have the host evaluate JavaScript source it supplies",
            Capability::JsNetwork => "make network requests through host JavaScript",
            Capability::JsStorage => "read and write browser-side persistent storage",
            Capability::JsMessaging => "post messages to other browsing contexts or workers",
            Capability::JsCrypto => "use the host's Web Crypto implementation",
            Capability::JsDom => "read or modify the host document",
            Capability::ContractStorageRead => "read contract storage",
            Capability::ContractStorageWrite => "write contract storage",
            Capability::ContractCall => "call another contract",
            Capability::ContractDelegateCall => {
                "execute another contract's code against its own state"
            }
            Capability::ContractValueTransfer => "move balance out of the contract",
            Capability::ContractCodeDeploy => "deploy or instantiate code",
            Capability::ContractSelfDestruct => "terminate the contract or an account",
            Capability::ContractRandomness => "draw on-chain randomness",
            Capability::ContractChainContext => {
                "read chain context such as block height, timestamp or caller"
            }
            Capability::ContractCrypto => "use host cryptographic primitives",
            Capability::ContractAccountKeys => "add or remove account access keys",
            Capability::HostMemory => "operate on a linear memory the host owns",
            Capability::HostTable => "operate on a function table the host owns",
            Capability::HostMutableGlobal => "read and write a global the host owns",
            Capability::HostTag => "receive exceptions thrown by the host",
            Capability::DebugLogging => "write to the host's log or debug channel",
            Capability::Unknown => "something this tool could not identify",
        }
    }

    /// Parse a capability identifier.
    pub fn parse(s: &str) -> Option<Capability> {
        Capability::ALL.iter().copied().find(|c| c.id() == s)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}
