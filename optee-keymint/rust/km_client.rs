// REE client scenario for km_ta.rs (single instance, multi session, not kept alive).
// One client provisions the boot info, ends early boot and uses a key, then closes its session,
// the last one: the instance is destroyed with its memory.  A new session reaches a new instance
// in early boot, where a different boot info is accepted (the core step of S4 in ../README.md).
// Rust bindings for the abstract lang/c model ABI, not the GP native ABI.

// The TA (its --ta id), its GP command for requests (WRITE, src/command.rs) and the opcodes of
// the requests (kmr-wire KeyMintOperation).
const KM_TA: u32 = 42;
const WRITE: u32 = 1024;
const SET_BOOT_INFO: u32 = 0x82;
const DEVICE_EARLY_BOOT_ENDED: u32 = 0x1c;
const DEVICE_GENERATE_KEY: u32 = 0x13;
const DEVICE_BEGIN: u32 = 0x1a;
const GET_ROOT_OF_TRUST: u32 = 0x72;

// Boot keys (roots of trust): the legitimate one and the attacker's.
const LEGIT_KEY: u32 = 100;
const ATTACKER_KEY: u32 = 200;

extern "C" {
    fn teecOpenSession(app: u32, out: *mut usize) -> u32;
    fn teecInvokeCommand(session: usize, command: u32, params: (u32, u32, *mut u32)) -> u32;
    fn teecCloseSession(session: usize) -> u32;
}

// The answers of the TA, in order (expected values in the comments; error names as in km_ta.rs).
pub fn run() -> [u32; 10] {
    let mut s1 = 0usize; let mut s2 = 0usize;
    let mut r = [0u32; 10];
    let mut o = 0u32;
    unsafe {
        teecOpenSession(KM_TA, &mut s1);
        teecInvokeCommand(s1, WRITE, (SET_BOOT_INFO, LEGIT_KEY, &mut o)); r[0] = o;      // OK
        teecInvokeCommand(s1, WRITE, (SET_BOOT_INFO, ATTACKER_KEY, &mut o)); r[1] = o;   // ROOT_OF_TRUST_ALREADY_SET
        teecInvokeCommand(s1, WRITE, (DEVICE_EARLY_BOOT_ENDED, 0, &mut o)); r[2] = o;           // OK
        teecInvokeCommand(s1, WRITE, (SET_BOOT_INFO, ATTACKER_KEY, &mut o)); r[3] = o;   // EARLY_BOOT_ENDED
        teecInvokeCommand(s1, WRITE, (DEVICE_GENERATE_KEY, 1, &mut o));                         // max uses 1
        let blob = o;
        teecInvokeCommand(s1, WRITE, (DEVICE_BEGIN, blob, &mut o)); r[4] = o;                 // OK
        teecInvokeCommand(s1, WRITE, (DEVICE_BEGIN, blob, &mut o)); r[5] = o;                 // KEY_MAX_OPS_EXCEEDED
        teecInvokeCommand(s1, WRITE, (GET_ROOT_OF_TRUST, 0, &mut o)); r[6] = o;          // LEGIT_KEY
        teecCloseSession(s1);                                                        // last session: instance destroyed
        teecOpenSession(KM_TA, &mut s2);
        teecInvokeCommand(s2, WRITE, (SET_BOOT_INFO, ATTACKER_KEY, &mut o)); r[7] = o;   // OK (new instance)
        teecInvokeCommand(s2, WRITE, (GET_ROOT_OF_TRUST, 0, &mut o)); r[8] = o;          // ATTACKER_KEY
        teecInvokeCommand(s2, WRITE, (DEVICE_BEGIN, blob, &mut o)); r[9] = o;                 // INVALID_KEY_BLOB
        teecCloseSession(s2);
    }
    r
}
