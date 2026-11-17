// A minimal KeyMint TA in the Rust subset of rust2maude, following the structure of the Google
// OP-TEE KeyMint TA (tee/optee/ta/keymint src/main.rs, ffced1f) and of kmr-ta
// (platform/system/keymint ta/src/lib.rs, fda4e68):
//   cmd_1024 (invoke_command, WRITE) -> handle_ipc_request -> KeyMintTa::process -> process_req
//   -> the method of the request (set_boot_info, early_boot_ended, generate_key, begin_operation,
//   get_root_of_trust).
// Kept: boot info and early boot, use-counted keys, the RoT binding of key blobs.  The
// differences from upstream are stated where they occur.
// Rust bindings for the abstract lang/c model ABI, not the GP native ABI.

// KeyMint ErrorCode values (wire/src/keymint.rs), without the sign (the model ABI passes u32).
const OK: u32 = 0;
const ROOT_OF_TRUST_ALREADY_SET: u32 = 1;
const TOO_MANY_OPERATIONS: u32 = 31;
const INVALID_KEY_BLOB: u32 = 33;
const KEY_MAX_OPS_EXCEEDED: u32 = 56;
const EARLY_BOOT_ENDED: u32 = 73;
const UNIMPLEMENTED: u32 = 100;
const ENCODING_ERROR: u32 = 20000;

// Request codes (kmr-wire KeyMintOperation, wire/src/types.rs).
const SET_BOOT_INFO: u32 = 0x82;
const DEVICE_EARLY_BOOT_ENDED: u32 = 0x1c;
const DEVICE_GENERATE_KEY: u32 = 0x13;
const DEVICE_BEGIN: u32 = 0x1a;
const GET_ROOT_OF_TRUST: u32 = 0x72;

// GlobalPlatform constants (TEE Internal Core API).
const TEE_TYPE_HMAC_SHA256: u32 = 0xA0000004;
const TEE_ATTR_SECRET_VALUE: u32 = 0xC0000000;
const TEE_ALG_HMAC_SHA256: u32 = 0x30000004;
const TEE_MODE_MAC: u32 = 4;
const KEY_BITS: u32 = 256;

// A key blob is the integer id * BLOB_ID + max_uses * BLOB_USES + rot, with rot < BLOB_USES and
// max_uses < BLOB_ID / BLOB_USES.  The real blob is encrypted with a KEK derived from the RoT;
// only that binding is kept: a blob made under another RoT does not decrypt (InvalidKeyBlob).
// Its authenticity is not modeled (the client cannot forge a blob in the scenarios).
const BLOB_ID: u32 = 10000;
const BLOB_USES: u32 = 1000;

// Key id 0 marks a free use-count slot.
const FREE: u32 = 0;

// KeyMintTa (lib.rs): the fields that this model keeps.  Upstream the TA has one KeyMintTa for
// the life of its instance (keymint_ta() in main.rs); here it is kept across commands by
// loadGlobals/storeGlobals (keymint-instance-globals.maude).  use_count is a table upstream; two slots here.
pub struct KeyMintTa {
    in_early_boot: bool,
    boot_info_set: bool,
    boot_key: u32,
    next_key_id: u32,
    slot0_key: u32,
    slot0_count: u32,
    slot1_key: u32,
    slot1_count: u32,
}

// PerformOpResponse (kmr-wire): the error code and the response (one integer here).
pub struct PerformOpResponse {
    error_code: u32,
    rsp: u32,
}

fn op_ok_rsp(rsp: u32) -> PerformOpResponse {
    PerformOpResponse { error_code: OK, rsp: rsp }
}

fn op_error_rsp(err: u32) -> PerformOpResponse {
    PerformOpResponse { error_code: err, rsp: 0 }
}

fn error_rsp(error_code: u32) -> PerformOpResponse {
    PerformOpResponse { error_code: error_code, rsp: 0 }
}

extern "C" {
    fn loadGlobals(g: *mut KeyMintTa);
    fn storeGlobals(g: *const KeyMintTa);
    fn allocateTransientObject(t: u32, n: u32, out: *mut usize) -> u32;
    fn initRefAttribute(id: u32, data: *const [u8; 32], out: *mut (u32, u32));
    fn populateTransientObject(h: usize, attrs: *const (u32, u32)) -> u32;
    fn allocOperation(a: u32, m: u32, n: u32, out: *mut usize) -> u32;
    fn setOperationKey(op: usize, key: usize) -> u32;
    fn macInit(op: usize, iv: *const [u8; 1]);
    fn macComputeFinal(op: usize, msg: *const [u8; 1], out: *mut [u8; 1]) -> u32;
    fn freeOperation(h: usize);
    fn freeTransientObject(h: usize);
}

// One HMAC computation with a key of the TA: the operation that begin starts, abstracted.
fn mac_once() -> u32 {
    let data = [1u8; 32]; let mut attr = (0u32, 0u32); let mut key = 0usize; let mut op = 0usize;
    let iv = [0u8]; let msg = [7u8]; let mut mac = [0u8];
    let rc;
    unsafe {
        allocateTransientObject(TEE_TYPE_HMAC_SHA256, KEY_BITS, &mut key);
        initRefAttribute(TEE_ATTR_SECRET_VALUE, &data, &mut attr);
        populateTransientObject(key, &attr);
        allocOperation(TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, KEY_BITS, &mut op);
        setOperationKey(op, key);
        macInit(op, &iv);
        rc = macComputeFinal(op, &msg, &mut mac);
        freeOperation(op);
        freeTransientObject(key);
    }
    rc
}

// The methods take and give back self (upstream &mut self: the subset has no field through a
// reference).  Result<T, Error> is (error code, value), OK for Ok.
impl KeyMintTa {
    // KeyMintTa::new: a new instance is in early boot, without boot info.
    pub fn new() -> KeyMintTa {
        KeyMintTa { in_early_boot: true, boot_info_set: false, boot_key: 0, next_key_id: 1,
                    slot0_key: FREE, slot0_count: 0, slot1_key: FREE, slot1_count: 0 }
    }

    // lib.rs set_boot_info.
    fn set_boot_info(mut self, key: u32) -> (KeyMintTa, u32) {
        if !self.in_early_boot {
            return (self, EARLY_BOOT_ENDED);
        }
        if self.boot_info_set {
            if self.boot_key == key {
                (self, OK)
            } else {
                (self, ROOT_OF_TRUST_ALREADY_SET)
            }
        } else {
            self.boot_info_set = true;
            self.boot_key = key;
            (self, OK)
        }
    }

    // lib.rs early_boot_ended (no precondition).
    fn early_boot_ended(mut self) -> (KeyMintTa, u32) {
        self.in_early_boot = false;
        (self, OK)
    }

    // lib.rs generate_key: a new key, its blob bound to the current RoT.
    fn generate_key(mut self, max_uses: u32) -> (KeyMintTa, u32, u32) {
        let id = self.next_key_id;
        self.next_key_id = id + 1;
        let blob = id * BLOB_ID + max_uses * BLOB_USES + self.boot_key;
        (self, OK, blob)
    }

    // lib.rs update_use_count: the slot of the key, else the first free slot.
    fn update_use_count(mut self, id: u32, max_uses: u32) -> (KeyMintTa, u32) {
        if self.slot0_key != id && self.slot1_key != id {
            if self.slot0_key == FREE { self.slot0_key = id; self.slot0_count = 0; }
            else if self.slot1_key == FREE { self.slot1_key = id; self.slot1_count = 0; }
        }
        if self.slot0_key == id {
            if self.slot0_count >= max_uses { return (self, KEY_MAX_OPS_EXCEEDED); }
            self.slot0_count = self.slot0_count + 1;
            (self, OK)
        } else if self.slot1_key == id {
            if self.slot1_count >= max_uses { return (self, KEY_MAX_OPS_EXCEEDED); }
            self.slot1_count = self.slot1_count + 1;
            (self, OK)
        } else {
            (self, TOO_MANY_OPERATIONS)
        }
    }

    // begin_operation (operation.rs): the blob is decrypted under the current RoT, the use count
    // is updated, and the operation starts.
    fn begin_operation(self, blob: u32) -> (KeyMintTa, u32, u32) {
        let id = blob / BLOB_ID;
        let max_uses = (blob % BLOB_ID) / BLOB_USES;
        let rot = blob % BLOB_USES;
        if rot != self.boot_key {
            return (self, INVALID_KEY_BLOB, 0);
        }
        let (ta, err) = self.update_use_count(id, max_uses);
        if err != OK {
            return (ta, err, 0);
        }
        let rc = mac_once();
        (ta, OK, rc)
    }

    // get_root_of_trust: the boot key that attestation would put in a certificate (upstream it
    // answers a challenge; only the RoT is kept).
    fn get_root_of_trust(self) -> (KeyMintTa, u32, u32) {
        let key = self.boot_key;
        (self, OK, key)
    }

    // lib.rs process: decode the request (a CBOR [code, request] upstream; here a code and one
    // argument), then process_req.  A request that does not decode gets EncodingError.
    pub fn process(self, code: u32, arg: u32) -> (KeyMintTa, PerformOpResponse) {
        if code == SET_BOOT_INFO || code == DEVICE_EARLY_BOOT_ENDED || code == DEVICE_GENERATE_KEY
            || code == DEVICE_BEGIN || code == GET_ROOT_OF_TRUST {
            self.process_req(code, arg)
        } else {
            (self, error_rsp(ENCODING_ERROR))
        }
    }

    // lib.rs process_req: select the method by the request, and build the response from what it
    // returns (op_ok_rsp / op_error_rsp).
    fn process_req(self, code: u32, arg: u32) -> (KeyMintTa, PerformOpResponse) {
        match code {
            SET_BOOT_INFO => {
                let (ta, err) = self.set_boot_info(arg);
                if err == OK { (ta, op_ok_rsp(0)) } else { (ta, op_error_rsp(err)) }
            }
            DEVICE_EARLY_BOOT_ENDED => {
                let (ta, err) = self.early_boot_ended();
                if err == OK { (ta, op_ok_rsp(0)) } else { (ta, op_error_rsp(err)) }
            }
            DEVICE_GENERATE_KEY => {
                let (ta, err, ret) = self.generate_key(arg);
                if err == OK { (ta, op_ok_rsp(ret)) } else { (ta, op_error_rsp(err)) }
            }
            DEVICE_BEGIN => {
                let (ta, err, ret) = self.begin_operation(arg);
                if err == OK { (ta, op_ok_rsp(ret)) } else { (ta, op_error_rsp(err)) }
            }
            GET_ROOT_OF_TRUST => {
                let (ta, err, ret) = self.get_root_of_trust();
                if err == OK { (ta, op_ok_rsp(ret)) } else { (ta, op_error_rsp(err)) }
            }
            _ => (self, error_rsp(UNIMPLEMENTED)),
        }
    }
}

// main.rs handle_ipc_request: the request goes to the KeyMintTa of the instance
// (keymint_ta().lock().0.process(req)); loadGlobals and storeGlobals stand for that instance
// memory.  Upstream the response is kept in the session and fetched by READ (1025).
fn handle_ipc_request(code: u32, arg: u32) -> PerformOpResponse {
    let mut ta = KeyMintTa::new();
    unsafe { loadGlobals(&mut ta); }
    let (ta, rsp) = ta.process(code, arg);
    unsafe { storeGlobals(&ta); }
    rsp
}

// main.rs invoke_command, command WRITE (1024).  The dispatch of invoke_command by command id
// is the model's (the id N selects the service cmd_N), so only WRITE is served.  The one output
// of the model ABI carries the error code, or the response when the code is OK.
pub fn cmd_1024(code: u32, arg: u32, out: &mut u32) {
    let rsp = handle_ipc_request(code, arg);
    if rsp.error_code != OK { *out = rsp.error_code; } else { *out = rsp.rsp; }
}
