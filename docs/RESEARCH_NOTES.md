# Research notes: what the reference material suggests for Memlapse

This document distils six reference sources that were read while designing
Memlapse into the ideas that matter for its development. It replaces the
folder of source documents that used to live in the repository; every claim
below carries a citation to the public original so it can be checked without
that folder. Each entry separates what the source says (quoted or cited) from
what that implies for Memlapse; sections 1 to 5 label the two parts
explicitly, and section 7 runs them together in one paragraph per entry. The
implication is always this project's own inference and should not be read as
the source's recommendation.

Entries are tagged against the code and the plan in
[ARCHITECTURE.md](ARCHITECTURE.md) as of September 2026:

- **New**: nothing in the code or the roadmap covers it.
- **Refines**: Memlapse has the feature; the source suggests a better version.
- **Corroborates**: independent support for a decision already taken.

The sources are abbreviated in citations as [T], [C], [K20], [K22], [D24] and
[V]; the full references and a note on each source's quality are at the end.

---

## 1. Signals available in a single snapshot

These extend the per-region injection score described in ARCHITECTURE.md,
which today combines region type, protection, an `MZ` header, a NOP sled and
Shannon entropy.

### 1.1 An `MZ` header is far stronger when the region is not a loaded module. Refines

**Source.** The recommended Volatility workflow is to "Compare loaded DLLs vs
modules registered in PEB" because a "Discrepancy = possible reflective DLL
injection" [C, §3 "Memory Forensics for In-Memory Attack Detection"]. The same
source lists T1055.002 reflective DLL injection as a DLL "loaded directly from
memory without calling Windows loader APIs, bypassing the standard DLL load
path" [C, "Common Fileless Malware Techniques"].

**Implication.** The +20 `MZ` signal fires on any PE header, including
legitimate modules mapped as `MEM_IMAGE`. Enumerating the loaded-module list
(`EnumProcessModulesEx` or the PEB loader list) and the backing file name of
each mapped region (`GetMappedFileNameW`) lets the scorer distinguish "PE header
in a region that is a known module" (benign) from "PE header in memory the
loader never saw" (reflective load). The region model currently stores only
base address, size, state, protection and type, so both the module list and the
mapped file name are new data. Recording them also gives the timeline a per-region
name column, which the hex view lacks today.

### 1.2 Compare executable image bytes in memory against the file on disk. New

**Source.** Memory forensics "can examine malware hooks and code outside the
function normal scope" and "can monitor malware behaviors such as API hooking,
DLL injection and Hidden processes" [K20, p. 47]. Module stomping, writing code
over a legitimately mapped image, is named in ARCHITECTURE.md as a known
evasion that the current structural rules only partially cover.

**Implication.** For `MEM_IMAGE` regions with execute permission, read the
in-memory bytes and compare them with the corresponding section of the file
named by `GetMappedFileNameW`, after applying relocations or, more simply,
ignoring the relocation entries. A mismatch in code bytes is evidence of an
inline hook or of module stomping, the third listed limitation of the scorer.
This is more expensive than the 256-byte head read, so it belongs in an
on-demand "verify image" action or a low-frequency sampler tier rather than the
one-second tick.

### 1.3 Scan region contents with YARA rules. New

**Source.** The Volatility workflow runs `windows.vadyarascan` with a rule file
to "Scan for Cobalt Strike beacons in memory" [C, §3]. Kara likewise cites the
use of "Yara, which can identify malware without downloading it" for fileless
code elements [K22, §2].

**Implication.** Memlapse already stores the first 256 bytes of every
executable region per sample. A YARA pass over stored heads, or over a full
region dump (see 4.1), would turn the heuristic score into an attributable
match. This introduces a third-party dependency (`yara-python`) and a rule
corpus, so it should be an optional extra and the rules should be user
supplied, not bundled.

### 1.4 Treat existing RWX regions as attack surface, not only as evidence. New

**Source.** Trovent's proof-of-concept does not allocate memory in the target.
It will "Scan all accessible processes for RWX memory regions", "Overwrite
discovered regions with custom shellcode" and then "Trigger the injected code
on demand", or the attacker can "wait for the legitimate process to execute it
naturally" [T, "Core Functionality"; "What Makes RWX Regions Dangerous?"]. The
defensive advice is to "Minimize use of RWX permissions in applications"
[T, "Protecting Against RWX Exploitation"].

**Implication.** Memlapse scores RWX as a sign that injection may have
happened. Trovent shows pre-existing RWX is also where the next injection will
land. A system-wide RWX census on the dashboard (which processes expose
writable executable memory, how much, and whether it is `MEM_PRIVATE`,
`MEM_MAPPED` or `MEM_IMAGE`) is a hardening view no single-process tool offers,
and it reuses the existing region sampler across many PIDs at a low rate.

### 1.5 Thread start addresses that fall outside any image. Shipped

**Source.** Every variant of the Trovent tool executes its payload with a new
thread in the target: `CreateRemoteThread`, then `New-NtThread`, then a direct
`NtCreateThreadEx` syscall [T, "Technical Implementation"; "Implementation
with NtObjectManager"; "Building tRWXix and tRWXiu"]. CyberDefenders' table of
injection chains ends four of its five rows in a thread primitive:
`CreateRemoteThread`, `RtlCreateUserThread`, `ResumeThread` after
`SetThreadContext`, and `QueueUserAPC` [C, §2 "Process Injection Detection via
API Call Monitoring"].

**Implication.** Memlapse records a thread count per process and nothing about
individual threads. Enumerating threads (`NtQuerySystemInformation` already
returns them) and resolving each start address
(`NtQueryInformationThread` with `ThreadQuerySetWin32StartAddress`) allows a
cheap, snapshot-level rule: a thread whose start address lies in a
`MEM_PRIVATE` or unnamed region, or in an RWX region, is suspicious on its own
and doubly so when that region also scores. It also gives the planned
"filter playback to one thread" feature something to show before ETW exists.

**Status.** Implemented in `win32/threads.py`, which reads each thread id
from the bulk table and then asks `NtQueryInformationThread` for the Win32
start address one thread at a time. The bulk table's own `StartAddress` is
no use: it holds the kernel start routine, and Windows zeroes it for an
unelevated caller. `analytics.regions_with_thread_starts` maps the addresses
onto the region map and `score_region` adds `THREAD_START_POINTS` (25) when
the containing region is executable and not image-backed, which puts a
private region with a thread on it at 75, the likely-injection band, on
those two signals alone. Live mode reads the addresses on the pool thread
and recordings store them per sample in `thread_snapshot`. Opening another
user's thread needs elevation; without it the addresses are unknown and the
rule stays silent.

### 1.6 Weight findings by how valuable the host process is. New

**Source.** The hunting hypothesis for in-memory code is to "Hunt for private
RWX regions in high-value processes like lsass.exe, svchost.exe, explorer.exe"
[C, "Threat Hunting Hypotheses", Hypothesis 3]. Injection into "long-running
processes" is how "malware can maintain a foothold" [T, "Why Attackers Love
Process Injection"].

**Implication.** The score is currently a property of the region alone. A small
process-context multiplier (system processes, LSASS, browsers and shells up;
known JIT hosts down) would rank the region table more usefully. It is the
positive counterpart of the JIT allowlist that ARCHITECTURE.md already plans.

### 1.7 Cross-view detection of hidden processes. New

**Source.** Memory forensic techniques "can monitor malware behaviors such as
API hooking, DLL injection and Hidden processes" [K20, p. 47]. Kara notes
"all processes are visible in memory at run-time" because "malware must expose
the majority of important information ... in memory to function" [K22, §1.3].

**Implication.** Memlapse lists processes from a single
`NtQuerySystemInformation` call. Comparing that list against a second, cheap
enumeration (for example `EnumProcesses`, or opening each PID in a range) and
against the parents named by surviving processes would surface a process
hidden from one view but not another. This is a low-priority idea for a
user-mode tool, since a rootkit that can unlink a process can usually hide from
both views, but it is nearly free to implement on top of the existing collector.

---

## 2. Signals that need time

Recording is what Memlapse has that a snapshot tool does not. Each entry here
is a detector that only exists because consecutive samples can be compared.

### 2.1 Content changes in a region whose protection never changes. Shipped

**Source.** The Trovent technique overwrites an RWX region that already exists,
so there is no allocation and no protection change to observe; the region's
bytes simply become different [T, "Core Functionality"; "Injecting shellcode
using NtObjectManager's Write-NtVirtualMemory"].

**Implication.** The planned RW-to-RX transition detector watches the
`protect` column across samples and would never fire on this attack. Hashing
each captured head (ARCHITECTURE.md already suggests hashing heads to save
space) makes a second temporal rule almost free: an executable region whose
head hash changes between samples while its protection and size stay the same
is being rewritten. Legitimate JIT code also does this, so the rule should feed
the score rather than raise an alert on its own.

**Status.** Implemented: heads are stored once per distinct content under
their SHA-256 hash, and playback compares consecutive samples with
`analytics.rewritten_regions`, adding 15 points to a rewritten private or
mapped region and 40 to a rewritten image region, where the benign
explanation is rarer but includes an EDR's own hooks, which is why 40 lands
in the review band rather than the likely-injection one. See the scoring
table in ARCHITECTURE.md.

### 2.2 Watch protection changes. Corroborates

**Source.** Trovent's defensive recommendation is to "Deploy EDR solutions that
monitor memory protection changes" [T, "Protecting Against RWX Exploitation"].
CyberDefenders calls RWX regions with no backing file "the single most reliable
indicator of reflective injection or shellcode execution" [C, §3, "Key
Indicator"].

**Implication.** Both statements support the planned `score_transition`
detector and the weight already given to unbacked executable memory.

### 2.3 Falling entropy is in-memory unpacking. New

**Source.** "While suspicious files can be hidden via encryption and packing,
all processes are visible in memory at run-time" [K22, §1.3]. "Polymorphic and
encrypted payloads ... can dynamically change and obfuscate malicious code"
[D24, §6.3].

**Implication.** The entropy signal today is a threshold on one sample. Over a
recording, a private executable region whose entropy drops from above 7 bits
per byte to code-like values (roughly 5.5 to 6.5) is a payload decrypting
itself in place. Store the head entropy per sample (one float per region) and
add a transition rule alongside RW-to-RX.

### 2.4 Catch short-lived processes and record lineage at creation. Part shipped

**Source.** Kovter "kills itself and makes regsvr32.exe its parent process as
soon as the process is created", after which "malicious URL connections will
start" [K22, §3.7]. The classic analyst tell is that "it is not common that an
excel process to have a msiexec.exe child process" [K22, §2]. CyberDefenders'
second hunting hypothesis is the same idea: "PowerShell is spawned by Word,
Excel, or a browser" [C, "Threat Hunting Hypotheses", Hypothesis 2].

**Implication.** The one-second process poll misses anything that lives for
less than a second, and the process model has no parent PID or command line.
Subscribing to the kernel process provider in the planned ETW collector
(process start and stop events carry parent PID, image path and command line)
would let Memlapse record every process that ever existed during a recording,
build the parent-child tree at creation time, and flag known-bad pairs. The
process table itself should gain parent PID and command line regardless, since
`NtQuerySystemInformation` already returns the parent.

**Status.** Half shipped. The bulk query already returned
`InheritedFromUniqueProcessId` and threw it away, so the process table now
carries `parent_pid` and shows a sortable Parent column. Windows does not
keep that field current, so it names the creator at creation time and may
point at a pid that has since exited or been reused. The rest, the command
line, a tree built at creation, and the ETW process events that would catch
a process living for less than one poll, is still to do.

### 2.5 Compare a process against a known-good baseline of itself. New

**Source.** "A good approach to increase accuracy during memory analysis is to
compare it with different memory structures or uninfected memories", with a
cited classification accuracy "above 90 % in almost every feature (function
calls, DLLs, API calls)" [K22, §1.3, citing Aghaeikheirabady et al. 2014]. The
same section notes this suits servers that "run distinct and unique programs".

**Implication.** Memlapse records one process over one session. A baseline
profile per image name (typical count of executable private regions, RWX bytes,
module set, entropy distribution) captured from a trusted run would let every
later run or instance be diffed against it, and would turn the JIT problem
around: a JIT host that always has 40 private executable regions is normal at
40 and suspicious at 400. Baselines fit naturally in the existing SQLite store
as a recording marked "reference".

### 2.6 Sequence detection over thread-tagged events. Refines

**Source.** Injection chains are recognisable as ordered API sequences,
"Individually, they may be legitimate, but in sequence, they constitute a
classic injection chain": remote-thread injection, process hollowing via
`NtMapViewOfSection`, `SetThreadContext` and `ResumeThread`, hook injection via
`SetWindowsHookEx`, and Early Bird APC injection [C, §2]. Trovent shows the
same chains issued as raw `Nt*` syscalls to avoid the well-known API names
[T, "Building tRWXix and tRWXiu"].

**Implication.** The ETW plan in ARCHITECTURE.md names allocation, free,
page-fault and image-load events. Two additions make the chains above visible:
thread-creation events (the kernel thread provider reports the creating
process, so a thread created in PID A by PID B is remote) and section-map
events. Because the syscall variants bypass user-mode API names but not the
kernel, kernel ETW sees them; this is the strongest argument for keeping ETW
as the forensic engine. Cross-process attribution (which PID caused a change in
the target) is a new column for `mem_event`.

---

## 3. Process-level context

Memlapse is a memory tool, but the sources keep pairing memory findings with a
small amount of process context to make them actionable.

### 3.1 Per-process network connections. New

**Source.** Kara's method checks "Abnormal process", "abnormal internet
traffic" and command logs together, and used `netstat` "to identify any unknown
port or connections that the fileless malware could try to communicate with"
[K22, §2; §3.3]. CyberDefenders' first hunting hypothesis is "Legitimate
processes are making outbound network connections that they never normally
make" [C, "Threat Hunting Hypotheses", Hypothesis 1].

**Implication.** A connections panel for the selected process (psutil's
`net_connections`, or `GetExtendedTcpTable` for a GIL-light path) costs little
and lets an analyst confirm the classic pairing of injected code plus an
unexpected outbound connection without leaving the tool. Recording connection
counts per sample also gives the timeline a network trace to line up with
memory events.

### 3.2 Continuous monitoring covers a gap antivirus leaves. Corroborates

**Source.** "Most of the antivirus solutions checks are done when a new
process starts and processes are already running on the system are choose
unsuspicious for the antivirus solutions" [K20, p. 48].

**Implication.** Sampling a running process on a timer is exactly the coverage
that start-time scanning lacks. This is a good sentence for the README's
motivation.

---

## 4. Data model, export and evidence handling

### 4.1 Dump a region or a process to a file. New

**Source.** The incident workflow dumps "suspicious process memory for further
analysis" with `windows.memmap --pid 1234 --dump` and captures a full memory
image with tools like WinPmem [C, §3; "Incident Response for Fileless Malware",
step 2].

**Implication.** Memlapse stores 256-byte heads and shows a hex preview. A
"save region bytes" action in the region view and a "write minidump" action
for the process (`MiniDumpWriteDump` with full memory) would hand evidence to
YARA, a disassembler or Volatility without a second tool. Both are one
`ReadProcessMemory` loop or one API call away from what exists.

### 4.2 Snapshot on alert. New

**Source.** "The evidence exists only in memory and will be lost on system
restart"; the first response steps are to isolate without
restarting and to capture memory immediately [C, "Incident Response for
Fileless Malware", steps 1 and 2].

**Implication.** When a region crosses the "likely injection" threshold during
a recording, Memlapse could automatically capture the full contents of that
region (not just its head) and optionally a process minidump, so the payload is
preserved even if the process exits before the analyst looks. This is the
recording engine's natural extension from "sample the map" to "preserve the
evidence".

### 4.3 Recordings as reproducible forensic artefacts. New

**Source.** Analysis reports should explain "the tools and techniques used in
the technical tests" so that "the same findings are obtained when the same
tools are used by different experts and the same processes are followed"
[K22, §3.4].

**Implication.** A recording already is a portable SQLite file. Adding a
manifest table (Memlapse version, host name, OS build, elevation state, sampler
interval, and a hash of the recording) and a "export recording" action would
make a recording something an analyst can hand over and someone else can
replay and re-score with confidence.

### 4.4 Tag reasons with ATT&CK technique IDs. Shipped

**Source.** Each detection in the guide is mapped to a MITRE ATT&CK technique,
"Mapping your detections to MITRE ATT&CK ensures coverage visibility and helps
identify gaps" [C, "MITRE ATT&CK Mapping Summary"]. Reflective DLL injection
is T1055.002, process injection T1055 [C, "Common Fileless Malware Techniques"].

**Implication.** ARCHITECTURE.md cites T1055 in its references, but the
human-readable `reasons` shown in the region tooltip do not. Appending the
technique ID to each reason string is a one-line change that makes exports
readable by anyone who works from ATT&CK.

**Status.** Implemented: every reason ends with its technique in square
brackets, from the constants `ATTACK_INJECTION` (T1055), `ATTACK_REFLECTIVE`
(T1620) and `ATTACK_PACKING` (T1027.002) in `analytics.py`, and the scoring
table in ARCHITECTURE.md carries the same column. The RWX and NOP sled
signals are deliberately left untagged: neither maps to a technique honestly.

### 4.5 Data-driven rules and portable findings. New

**Source.** Sigma rules "provide a platform-agnostic way to describe detection
logic" and "can be converted to Splunk SPL, Microsoft Sentinel KQL, Elastic
DSL" [C, "Detection Rules: Sigma Signatures for Fileless Activity"].

**Implication.** The scorer's weights and thresholds are constants in
`analytics.py`. Moving them to a small declarative table (and emitting findings
as JSON with the same field names the reasons use) would let users tune weights
without editing code and feed Memlapse findings into whatever they already
collect. This is a modest refactor, not a new engine.

---

## 5. Evasion, false positives and tuning

### 5.1 API-name detection is evadable; memory state is not. Corroborates

**Source.** Trovent's first tool "is susceptible to detection by antivirus
software and EDR solutions" because of "well-known malware APIs"; the later
versions use `NtObjectManager` and then direct syscalls (`NtOpenProcess`,
`NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtAllocateVirtualMemory`) to gain
"significantly lower detection risk" [T, "The Stealth Challenge"; "Building
tRWXix and tRWXiu"].

**Implication.** Whatever API the attacker used, the result in the target's
address space is the same: bytes that changed, a thread that started in
private memory, or a protection that flipped. Memlapse inspects the result, not
the call, so the evasion in this article does not apply to it. It does apply to
any future detector built on user-mode API hooking, which is a reason to prefer
kernel ETW over hooks.

### 5.2 Memlapse itself looks like an injector to an EDR. Corroborates

**Source.** The attack tools use "OpenProcess", "VirtualQueryEx",
"WriteProcessMemory" and "CreateRemoteThread", "Windows APIs commonly
associated with malware development" [T, "Technical Implementation"].

**Implication.** Memlapse calls the first two of these on every tick and reads
memory with `ReadProcessMemory`. ARCHITECTURE.md already warns that EDR may
flag it. A note in the README, and never adding a write or thread-creation
primitive, keeps the tool on the right side of that line.

### 5.3 Behaviour-based detection trades false positives for coverage. Corroborates

**Source.** "The major disadvantage of behavior-based is considerable to
false-positive rate and excessive monitoring time" [K20, p. 47]. "The high
level of false-positive behavior detection is a key downside of this strategy"
[K22, §2]. Sigma rule authors list "Legitimate admin scripts (verify with
context)" as expected false positives [C, sigma_rule_01].

**Implication.** Supports the plan to tune thresholds against a JIT-heavy
baseline and to allowlist known JIT hosts, and strengthens the case for 2.5
(per-image baselines) as the systematic form of that tuning.

### 5.4 Dumps and sandboxes are slow, risky and evadable; live sampling is not. Corroborates

**Source.** Taking a memory dump "requires that it be started in the operating
system, which puts the system in danger", "slows down the process" and "takes
the system out of real-time mode"; sandbox-aware malware "has been known to
shut down instantly" [K22, §4]. Sandboxes and multi-engine scanners "struggled
to detect threats in fileless malware" [D24, §9].

**Implication.** This is the positioning argument for Memlapse: continuous,
low-overhead sampling of a live process on the real host, with history, sits
between a point-in-time dump and a full EDR.

### 5.5 Anomaly detection over per-process feature vectors. Refines

**Source.** Machine learning "can also be applied for a comparison technique"
so that "Comparison of a clean memory and an infected memory can be automated"
[K22, §4]. "Unsupervised learning algorithms ... can identify anomalous
patterns in system behavior without predefined labels" [D24, §5.4].

**Implication.** The dashboard's z-score spike detector works on system RAM.
The same code applied to a per-process vector (count of executable private
regions, RWX bytes, number of threads, head-hash churn) would flag structural
anomalies over a recording without any model training. Full machine learning is
out of scope for a dependency-light desktop tool; the z-score is not.

### 5.6 A decoy RWX region as a canary. New, speculative

**Source.** Researchers "are exploring the use of deception technologies, such
as honeypots and honeytokens, to lure and trap fileless malware" [D24, §8.1].
Trovent shows injectors that scan every accessible process for RWX regions to
overwrite [T, "Core Functionality"].

**Implication.** Combining the two: Memlapse could allocate a small RWX region
in its own process (or a helper) filled with a known pattern, and check it each
tick. Any change means something on the host is writing into foreign RWX
memory. This is the one entry here that neither source proposes; it follows
from putting the two together and is recorded as an idea to test, not a plan.

---

## 6. Adjacent, and deliberately out of scope

The fileless-malware sources spend most of their length on things that are
real detection layers but not memory inspection: PowerShell script-block
logging and constrained language mode [C, §1; K20, p. 48], registry-resident
payloads such as Poweliks and Kovter [K22, §1.1, §3.7], WMI event-subscription
persistence [C, §4; K22, §1.1], AMSI telemetry [C, §5], LOLBin parent-child
rules [C, sigma_rule_02], and organisational controls such as application
allowlisting, zero trust and user training [D24, §7]. Memlapse should stay a
memory tool. The one exception is 2.4: process lineage is cheap to record and
is the context every one of these sources reaches for first.

---

## 7. Lessons from a commercial detection platform

The VMware vDefend Security Services Platform documentation [V] is a network
security product manual, not a memory forensics text. It says nothing about
page protections, entropy, YARA, `MZ` headers, `VirtualAlloc` or ETW, so it
neither supports nor contradicts the region-level point values in
ARCHITECTURE.md, and its fileless coverage is script-centric (PowerShell,
VBScript and JScript captured through AMSI) and detect-only [V, p. 423]. Native
code injection, which is Memlapse's target, is outside its stated scope. What
it does offer is a worked example of how a mature product turns raw detections
into something an analyst can use: scoring, aggregation, tuning, retention and
presentation. Those layers are where Memlapse is thinnest, so this section is
long relative to the product's direct relevance.

### 7.1 Scoring

**Three verdict bands with a lower "suspicious" edge. Refines.** Scores are
banded 0 to 29 benign, 30 to 69 suspicious, 70 to 100 malicious, and 30 is
also the cutoff for forwarding an event to correlation: "Suspicious or
malicious file events (scoring 30 or above) are sent to Network Detection and
Response" [V, p. 458, p. 486]. Memlapse's review threshold of 50 hides a band
the product considers worth a second look. A three-band display (with 30 as
the floor of "review") costs nothing and matches the additive scale already in
use. **Shipped:** `RegionVerdict.band` returns low, review or likely
injection from `REVIEW_SCORE` (30) and `LIKELY_SCORE` (75), and the band
leads the region tooltip.

**Separate confidence from severity. New.** Impact "is initially Confidence *
Severity / 100" [V, p. 513]; severity is a property of the threat type,
confidence of how it was detected, and a per-detector baseline confidence
rises "if the activity looks periodic" or repeats within one event [V,
p. 512]. Memlapse's additive score mixes the two. Giving each heuristic its
own confidence, and raising it when a region stays executable across many
samples, would let a single RWX region (severe, uncertain) rank differently
from a repeated `MZ`-in-private-memory hit (severe, confident). This pairs
naturally with the temporal rules in section 2.

**Score 0 and minus one are reserved, and neither means benign. New.**
Suppressed detections keep score 0; allowlisted files keep their row with
"Uninspected files have a score of -1" [V, p. 454]. Suppressing a verdict
leaves the underlying score alone: "The threat score of the file does not
change. However, the color of the bubble changes to gray" [V, p. 447]. The
planned JIT allowlist should follow this: keep the region in the table with its
raw score and a distinct "allowlisted" verdict, never filter it out.

**Process score is the maximum of its parts. New.** The Processes tab shows
"the maximum threat score computed for the in-memory script execution" for
each process, and campaign graph nodes are coloured by "the highest impact
score from its associated detections" [V, p. 458, p. 506]. Memlapse scores
regions only. A process column holding the maximum region score plus a count
of scored regions would give the process table one sortable threat column and
a colouring rule.

**Escalate several medium findings on one target. New.** The "Multiple
Anomaly Events on Workload" rule states that "a combination of detections with
lower severity is escalated" [V, p. 502]. Several regions in the review band
inside one process could lift that process into the likely-injection band even
if no single region reaches 75.

**Strict and relaxed modes. New.** The segmentation score offers a Strict
mode "for a more accurate score" and a Relaxed mode with "less severe
penalties" [V, p. 258, p. 273]. A developer-machine mode that lowers the
weight of executable private memory for known JIT hosts, without hiding them,
is the Memlapse analogue and a gentler tool than an allowlist.

### 7.2 Aggregation and correlation

**Aggregate repeats into one finding with a count and a history. New.** A
detection "does not correspond to a single instance of malicious activity
detected at a specific point in time"; the platform "aggregates similar
activity affecting the same workload, within a period of up to 24 hours",
shows one row with Total Inspections, First Inspected and Last Inspected, and
keeps "the history of all previous inspections" one click away [V, p. 455 to
457, p. 511]. Memlapse stores one region map per sample, so a region that
scores for ten minutes produces six hundred identical verdicts. A findings
table keyed on process, region base and heuristic, with first seen, last seen
and hit count, is the missing layer between samples and the analyst.

**Multi-step rules with an outer window, an inter-step gap and per-step
thresholds. New.** The Fileless Downloader Chain rule requires two events
scoring 70 or more where "All events must occur within a 1-hour window on the
compute, with a maximum of 15 minutes between any two consecutive events"
[V, p. 502]. The planned RW-to-RX detector is a two-step temporal rule of the
same shape; it should carry the same three parameters explicitly rather than
implying "consecutive samples".

**Campaigns as a named container. New.** Detections are correlated into a
campaign that is auto-named "using a heuristic, based on the malicious
activity that is initially correlated", renameable, timed, and scored by how
many assets it touches [V, p. 485, p. 500 to 503]. An "incident" grouping an
injector process, its target and the regions involved would be the equivalent
unit on Memlapse's timeline once ETW attribution exists.

**Record who acted and who was acted on as separate fields. New.** "Attack
direction indicates which system is malicious, marked in red", drawn apart
from the flow direction because "traffic might flow from System A to B, but B
could be the attacker" [V, p. 326, p. 507]. When ETW arrives, the allocating
or writing thread may live in a different process from the executing one;
storing both on the event avoids the same confusion.

**Refuse to report from too little data. New.** Detectors report
NOT_ENOUGH_BASELINE when they "could not report events because the baseline
size was insufficient for event detection" [V, p. 214]. The dashboard's
z-score spikes and least-squares leak rate should do the same instead of
presenting a confident number from three points. **Shipped:** the interpret
strip reads "collecting baseline, N of 30 samples" until
`MIN_INSIGHT_SAMPLES` have arrived, and states no rate or anomaly before
then.

**Statistics propose, rules confirm. Refines.** The traffic analytics engine
"combines ML-driven behavior modeling with rule-based analytics" because "not
every anomaly is a security threat" [V, p. 411]. A RAM spike alone is
informational; a spike coinciding with a new executable private region in the
same process is a finding. Joining the dashboard's anomaly detector to the
region scorer is the cheap version of this.

### 7.3 Tuning and allowlisting

**Per-detector thresholds and exclusions. New.** Every detector has its own
enable toggle, a "Likelihood (Threshold)" slider ("For a detection that falls
below the threshold, the system discards the suspicious traffic event") and
its own exclusion lists, with a distinction between static lists and groups
evaluated at run time [V, p. 411 to 417]. Memlapse has one global pair of
thresholds. Per-heuristic thresholds, and exclusions that can be a predicate
(image name pattern, signer) rather than a PID, would let a user exempt the
CLR from the private-executable rule without exempting it from the `MZ` rule.

**Allowlisting is audited and reversible. Refines.** Suppressing a verdict
logs the override "for auditing purposes", emits a new Uninspected event, and
removing the entry re-enables analysis [V, p. 447, p. 453]. Any Memlapse
allowlist should be keyed on something durable (image path plus publisher, or
head hash), written to the recording, and shown rather than applied silently.

**Reputation of the backing image. New.** Reputation includes the publisher,
whether the file is signed, the signing authority and a trust category, with
"Highly Trusted" reserved for vendors such as Microsoft, Apple and Adobe
[V, p. 425, p. 426]. The +30 executable `MEM_MAPPED` rule fires regardless of
what backs the region. Checking the Authenticode signature of the mapped file
would down-weight signed images from known vendors while leaving unsigned
mapped executables at full score. This complements 1.1 and 1.2.

**Findings carry a triage state. New.** The triage menu offers Mark as
Ignored ("Remove this and future event occurrences"), Mark as Resolved and
Mark as In-progress, applied to future occurrences of the same signature
[V, p. 566, p. 571]. Alarms follow Open, Acknowledged, Suppressed for a
period, Resolved [V, p. 220, p. 221]. A finding keyed on head hash or (image,
region type) that remembers it was acknowledged would stop a known leaky or
JIT-heavy process from re-alerting every sample.

### 7.4 Storage and retention

**Adaptive retention and a clean pause. New.** Retention is "dynamically
adjusted" from stored size and daily intake, so a 30-day setting becomes 15
days when the disk fills on day 15; ingestion pauses when "available space <
20GB or 10% of total storage, whichever is higher" and resumes only with two
days of predicted headroom [V, p. 414, p. 415]. Memlapse's recorder has no
retention policy and no disk check; a size cap that drops the oldest samples,
shows the effective retention, and pauses with a visible banner is the direct
transfer.

**Tiered roll-up of time series. New.** Numeric series are kept at five-minute
resolution for a week, hourly for a month and daily for a year; point-in-time
values expire after a day; status strings are stored only on change; query
granularity is chosen from the visible range so a long window does not return
millions of points [V, p. 192 to 195]. The dashboard's usage timeline and the
recording scrubber could both pick bucket size from the visible range, and
long recordings could downsample old samples the same way.

**Count what you drop. New.** The platform reports rate-limited and purged
events by category, and the sensor separates "Packets Dropped", meaning
overwhelmed, from bypassed, meaning deliberately skipped [V, p. 214, p. 537].
Memlapse's latest-only delivery discards intermediate samples by design;
counting and showing skipped samples per collector makes that honest.
**Shipped:** the `skipped` counter in `collectors/base.py` now reaches the
status bar, which reads "N processes, M polls dropped" whenever M is above
zero.

**State your limits and warn at 90 percent. New.** The product publishes
numeric ceilings (events per window, rows displayed, file size analysed) and
shows "a warning banner" when a configured maximum reaches 90 percent
[V, p. 27, p. 230, p. 411]. Memlapse should document its own maxima (samples
per recording, regions per sample rendered) and warn before hitting them.

### 7.5 Presentation

**A bubble timeline with one lane per verdict. New.** Files and processes are
plotted as bubbles on a time axis, one lane per verdict, where "The number on
the bubble denotes the threat score computed for the file", bubble size
encodes how many inspections were merged, allowlisted items move to a gray
lane, and clicking a bubble jumps to the table row [V, p. 447, p. 454 to 459].
A window slider under the chart splits merged bubbles as the range narrows
[V, p. 419]. This maps directly onto Memlapse's recording timeline: a bubble
at the sample where a region first crossed a threshold, laned by verdict.

**Show the score and its components. New.** Impact appears as a number in a
hexagon with a coloured border and a text label, and hovering reveals the
confidence and severity behind it [V, p. 419]. If Memlapse adopts confidence
times severity, this is the display.

**Every detector explains itself. New.** The detector name in a row opens a
dialog with its goal, ATT&CK category and an abstract [V, p. 419]. Each
Memlapse reason string (private executable, RWX, NOP sled, entropy) could open
a short note on what the signal means and its common false positives, which
is also where the JIT caveat belongs.

**Health vocabulary for collectors. New.** Components report OK, Degraded
("usually happens when the system is under heavy load"), Down, Disabled,
Disconnected or Not Available, each with a suggested action [V, p. 538,
p. 539]. A collector indicator that reads Degraded while the sampler is
skipping and Not Available before the first sample would communicate
latest-only delivery to the user.

**Filters drive chart and table together and are shareable. New.** Filters
apply to both views at once and a Copy URL button captures them [V, p. 455,
p. 508, p. 509]. For a desktop tool, a saved filter preset and a filter line in
the CSV header are the equivalent.

### 7.6 Export

**Stream findings as JSON on create and update. New.** Detections and
campaigns are pushed as JSON on four triggers (created, updated, for each)
to a SIEM endpoint [V, p. 514, p. 515]. A local version, appending one JSON
line whenever a finding is created or its score changes, would make recordings
consumable by other tools with almost no code. The event record's field list
(hashes, size, type, first and last time, verdict, score, blocked and
allowlisted flags) is a reasonable checklist for what each line should carry
[V, p. 467 to 469].

**Report formats. New.** Analysis reports export to XML, JSON and PDF with
downloadable artefacts, and rule analysis exports "a separate CSV file for
each anomaly type" inside one archive [V, p. 386, p. 460, p. 462]. Memlapse has
CSV and JSON of the dashboard window; a printable summary of a recording, and
a per-heuristic split of findings, would complete the set.

---

## Sources

Abbreviations used in the citations above. Page numbers for [K20] are the
journal's printed page numbers. [K22] is cited by section number because the
copy read was a corrected proof whose pagination differs from the published
article. [D24] is cited by section number for the same reason. Web articles
are cited by their section headings.

- **[T]** Makarov, S. *Deep Dive into Stealthy Process Injection Techniques:
  Exploiting RWX Memory Regions.* Trovent Security GmbH, 3 September 2025.
  <https://trovent.io/en/exploiting-rwx-memory-regions/>.
  A practitioner write-up with working proof-of-concept tools (tRWXi, tRWXix,
  tRWXiu). Short, concrete and the most directly useful of the six for
  Memlapse's detection design.
- **[C]** CyberDefenders. *Fileless Malware Detection: How SOC Teams Hunt
  In-Memory Attacks.* 13 May 2026.
  <https://cyberdefenders.org/blog/fileless-malware-soc-detection/>.
  A SOC-oriented guide. Vendor training content, but the injection-chain
  table, the Volatility workflow and the hunting hypotheses are standard
  practice and well stated.
- **[K20]** Khushali, V. *A Review on Fileless Malware Analysis Techniques.*
  International Journal of Engineering Research and Technology (IJERT), vol. 9,
  issue 5, May 2020, pp. 46 to 49. Paper IJERTV9IS050068.
  <https://doi.org/10.17577/ijertv9is050068>.
  Published under a Creative Commons Attribution 4.0 licence. A brief student
  literature review; useful mainly for the taxonomy of what memory forensics
  can see (hooks, injected DLLs, hidden processes) and the observation about
  start-time scanning.
- **[K22]** Kara, I. *Fileless malware threats: Recent advances, analysis
  approach through memory forensics and research challenges.* Expert Systems
  with Applications, vol. 214, article 119133, 2023 (accepted 21 October 2022).
  <https://doi.org/10.1016/j.eswa.2022.119133>.
  Peer-reviewed. The copy read was the corrected proof. The literature review
  and the Kovter case study are the substance; the baseline-comparison idea in
  §1.3 is the most valuable single paragraph in the set.
- **[D24]** Dewan, R. and Sivakumar, V. *A Deep Dive into Detecting and
  Investigating Fileless Malware.* SSRN preprint 4932008, 10 August 2024.
  <https://ssrn.com/abstract=4932008>.
  Not peer reviewed. A revised version with an additional author appeared in
  the International Journal of Sensors, Wireless Communications and Control,
  vol. 15, no. 3, September 2025 (doi:10.2174/0122103279377106250507052410);
  that version was not read.
  A general survey with little technical depth; cited here
  only where it states a widely held position (polymorphic payloads,
  unsupervised anomaly detection, deception).
- **[V]** VMware by Broadcom. *Security Services Platform 5.1* (product
  documentation, PDF export, 576 pages).
  <https://techdocs.broadcom.com/us/en/vmware-security-load-balancing/vdefend/security-services-platform/5-1.html>.
  Administration documentation for a network security platform (vDefend
  Security Intelligence, Network Detection and Response, Malware Prevention).
  Cited by PDF page number of the export that was read. Most of it concerns
  deployment and networking; the transferable material is in how a commercial
  product scores, aggregates, tunes, retains and presents detections, which is
  the subject of section 7.
