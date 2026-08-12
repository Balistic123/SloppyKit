import { establishPrimitive, fakeCellReleased } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";

const Q = new URLSearchParams(location.search);
const ARMED = Q.get("go") === "1";
const BUILD = () => window.P2JB_BUILD || "dev";
const MAX_ATTEMPTS = 1;

const PAYLOADS = [
    { name: "ftpsrv-ps5.elf", label: "FTP Server" },
    { name: "gdbsrv-ps5.elf", label: "GDB Server" },
    { name: "klogsrv-ps5.elf", label: "Kernel Log" },
    { name: "shsrv-ps5.elf", label: "Shell" },
    { name: "websrv-ps5.elf", label: "Web Server" }
];
const PAYLOAD_PORT = 9021;
const PAYLOAD_BUFFER_SIZE = 0x10000;
const PAYLOAD_MAX_SIZE = 0x200000;

const stageEl = document.getElementById("stage");
const logEl = document.getElementById("log");
const menuEl = document.getElementById("menu");
const verdictEl = document.getElementById("verdict");

const nogcHard = { carrier: null, p: null, chain: null };

let P = null;
let chain = null;
let chainDead = "";
let errConvention = "posix";
let payloadSendBusy = false;
let payloadSendStore = null;
let payloadSockaddrStore = null;
let payloadSocketOptionStore = null;
let payloadSendTimeoutStore = null;

function stage(text, cls) {
    stageEl.textContent = text;
    stageEl.className = cls || "";
}

function logLine(text) {
    logEl.textContent += text + "\n";
    logEl.scrollTop = logEl.scrollHeight;
}

async function settleBeforePrepare() {
    if (typeof globalThis.gc === "function") {
        try { globalThis.gc(); globalThis.gc(); globalThis.gc(); } catch (e) { }
    }
    await new Promise(r => setTimeout(r, 2000));
    if (typeof globalThis.gc === "function") {
        try { globalThis.gc(); } catch (e) { }
    }
}

function loadScript(src) {
    return new Promise((resolve, reject) => {
        const s = document.createElement("script");
        s.src = src;
        s.onload = () => resolve();
        s.onerror = () => reject(new Error("script load failed: " + src));
        document.head.appendChild(s);
    });
}

function waitOffsetsReady() {
    return new Promise((resolve, reject) => {
        const s = document.querySelector('script[src^="../offsets/"]');
        if (!s) return reject(new Error("offsets script missing"));
        if (typeof OFFSET_wk_vtable_first_element !== "undefined") return resolve(s.src);
        s.addEventListener("load", () => resolve(s.src));
        s.addEventListener("error", () => reject(new Error("offsets 404: " + s.src)));
    });
}

async function loadChainScripts() {
    const B = encodeURIComponent(BUILD());
    logLine("loading chain scripts after WebKit purge");
    await loadScript("rop.js?b=" + B);
    await loadScript("main.js?b=" + B);
    window.offsetsReady = waitOffsetsReady();
    await loadScript("syscalls.js?b=" + B);
    await window.offsetsReady;
}

async function preflight() {
    if (typeof prepare !== "function")
        throw new Error("main.js did not evaluate");
    if (typeof worker_rop !== "function")
        throw new Error("rop.js did not evaluate");
    if (typeof SYS_GETPID === "undefined")
        throw new Error("syscalls.js did not evaluate");
    logLine("offsets fw=" + window.fw_str);
}

function assertInt64Identity() {
    if (globalThis.int64 !== int64)
        throw new Error("int64 identity mismatch");
}

async function bootWebKit() {
    if (globalThis.p && typeof globalThis.p.read8 === "function") {
        logLine("primitive reused");
        return;
    }

    stage("WebKit (1 attempt)");
    try { history.replaceState(null, ""); } catch (e) { }
    if (typeof globalThis.gc === "function") {
        try { globalThis.gc(); } catch (e) { }
    }
    await new Promise(r => setTimeout(r, 750));

    const carrier = await establishPrimitive({
        maxAttempts: MAX_ATTEMPTS,
        onEvent(tag, detail, attempt) {
            if (tag === "ATTEMPT-START")
                stage("WebKit attempt " + attempt + "…");
        }
    });

    nogcHard.carrier = carrier;
    installWindowP(carrier, { onEvent() { } });
    nogcHard.carrier = null;

    if (!pairStatus.promoted)
        throw new Error("pair not promoted: " + pairStatus.error);
    if (!fakeCellReleased())
        throw new Error("exploit graph not released before prepare");

    logLine("primitive up released=" + fakeCellReleased()
        + " history=" + (history.state === null));

    if (typeof globalThis.gc === "function") {
        try { globalThis.gc(); } catch (e) { }
    }
    await new Promise(r => setTimeout(r, 1000));
}

async function bootPrepare() {
    const p = globalThis.p;
    if (!p || typeof p.read8 !== "function")
        throw new Error("window.p missing");
    nogcHard.p = p;
    assertInt64Identity();

    await settleBeforePrepare();

    stage("prepare()");
    logLine("prepare() enter");
    const prepared = await prepare(p, {
        menu: true,
        stackSize: 0x40000,
        reservedStack: 0x8000
    });
    P = prepared.p;
    chain = prepared.chain;
    nogcHard.chain = chain;
    logLine("prepare() ok");
}

function classify(raw) {
    const s32 = ((raw.low << 0) >> 0);
    return { s32, failed: s32 < 0 };
}

function errText(res) {
    if (!res.failed) return "";
    if (errConvention === "posix") return "errno " + (-res.s32);
    return "raw " + res.hex;
}

async function sys(num, a, b, c, d, e, f) {
    if (chainDead)
        throw new Error("chain dead: " + chainDead);
    const raw = await chain.syscall(num, a, b, c, d, e, f);
    const cl = classify(raw);
    return { raw, s32: cl.s32, failed: cl.failed,
        hex: "0x" + raw.toString(),
        errText: errText({ failed: cl.failed, s32: cl.s32, hex: "0x" + raw.toString() }) };
}

function mem(n) {
    const ptr = P.malloc(n, 1);
    return { ptr, u8: ptr.backing };
}

function preparePayloadSender() {
    if (payloadSendStore === null)
        payloadSendStore = mem(PAYLOAD_BUFFER_SIZE);
    if (payloadSockaddrStore === null) {
        payloadSockaddrStore = mem(0x10);
        const addr = payloadSockaddrStore.u8;
        addr.fill(0);
        addr[0] = 0x10;
        addr[1] = 0x02;
        addr[2] = (PAYLOAD_PORT >>> 8) & 0xff;
        addr[3] = PAYLOAD_PORT & 0xff;
        addr[4] = 127;
        addr[5] = 0;
        addr[6] = 0;
        addr[7] = 1;
    }
    if (payloadSocketOptionStore === null) {
        payloadSocketOptionStore = mem(4);
        payloadSocketOptionStore.u8.fill(0);
        payloadSocketOptionStore.u8[0] = 1;
    }
    if (payloadSendTimeoutStore === null) {
        payloadSendTimeoutStore = mem(0x10);
        payloadSendTimeoutStore.u8.fill(0);
        payloadSendTimeoutStore.u8[0] = 15;
    }
}

async function probeExistingElfldr() {
    preparePayloadSender();
    const sock = await sys(SYS_SOCKET, 2, 1, 0);
    if (sock.failed || sock.s32 < 0)
        return false;
    const fd = sock.s32;
    let reachable = false;
    try {
        const conn = await sys(SYS_CONNECT, fd, payloadSockaddrStore.ptr, 0x10);
        reachable = !conn.failed && conn.s32 === 0;
        if (!reachable) {
            const sock2 = await sys(SYS_SOCKET, 2, 1, 0);
            if (!sock2.failed && sock2.s32 >= 0) {
                const bindRes = await sys(SYS_BIND, sock2.s32,
                    payloadSockaddrStore.ptr, 0x10);
                await sys(SYS_CLOSE, sock2.s32);
                reachable = bindRes.failed || bindRes.s32 < 0;
            }
        }
    } finally {
        await sys(SYS_CLOSE, fd);
    }
    return reachable;
}

async function sendPayload(name) {
    if (payloadSendBusy) return;
    payloadSendBusy = true;
    stage("Sending " + name + "…");
    try {
        const response = await fetch("../payloads/" + encodeURIComponent(name),
            { cache: "no-store" });
        if (!response.ok)
            throw new Error("fetch failed: HTTP " + response.status);
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (!bytes.length) throw new Error("empty payload");
        if (bytes.length > PAYLOAD_MAX_SIZE)
            throw new Error("payload exceeds 2 MiB");
        if (bytes[0] !== 0x7f || bytes[1] !== 0x45)
            throw new Error("not an ELF");

        preparePayloadSender();
        let fd = -1;
        let sent = 0;
        try {
            let r = await sys(SYS_SOCKET, 2, 1, 0);
            if (r.failed || r.s32 < 0) throw new Error("socket: " + r.errText);
            fd = r.s32;

            r = await sys(SYS_SETSOCKOPT, fd, 0xffff, 0x0800,
                payloadSocketOptionStore.ptr, 4);
            if (r.failed || r.s32 !== 0)
                throw new Error("setsockopt: " + r.errText);

            r = await sys(SYS_SETSOCKOPT, fd, 0xffff, 0x1005,
                payloadSendTimeoutStore.ptr, 0x10);
            if (r.failed || r.s32 !== 0)
                throw new Error("sndtimeo: " + r.errText);

            r = await sys(SYS_CONNECT, fd, payloadSockaddrStore.ptr, 0x10);
            if (r.failed || r.s32 !== 0)
                throw new Error("connect: " + r.errText);

            while (sent < bytes.length) {
                const block = Math.min(PAYLOAD_BUFFER_SIZE, bytes.length - sent);
                payloadSendStore.u8.set(bytes.subarray(sent, sent + block), 0);
                let blockSent = 0;
                while (blockSent < block) {
                    r = await sys(SYS_WRITE, fd,
                        payloadSendStore.ptr.add32(blockSent), block - blockSent);
                    if (r.failed || r.s32 <= 0)
                        throw new Error("write: " + r.errText);
                    blockSent += r.s32;
                }
                sent += block;
            }
        } finally {
            if (fd >= 0) await sys(SYS_CLOSE, fd);
        }
        stage(name + " sent (" + sent + " bytes)", "ok");
        logLine("OK " + name + " " + sent + " bytes");
    } catch (e) {
        stage("Send failed: " + ((e && e.message) || e), "bad");
        logLine("FAIL " + name + ": " + ((e && e.message) || e));
    } finally {
        payloadSendBusy = false;
    }
}

function showMenu() {
    menuEl.innerHTML = "";
    menuEl.className = "on";
    verdictEl.textContent = "Payload manager ready. Pick a payload below.";
    for (const item of PAYLOADS) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "payloadBtn";
        btn.textContent = item.label;
        btn.addEventListener("click", () => sendPayload(item.name));
        menuEl.appendChild(btn);
    }
    try { menuEl.firstChild.focus(); } catch (e) { }
}

async function main() {
    if (!ARMED) {
        stage("Add ?go=1 or use the index PAYLOAD MENU ONLY button.");
        return;
    }

    document.getElementById("buildTag").textContent = "Build " + BUILD() + " (menu)";
    logLine("menu boot build=" + BUILD());

    await bootWebKit();
    await loadChainScripts();
    await preflight();
    await bootPrepare();

    stage("Checking elfldr on 127.0.0.1:9021…");
    if (!(await probeExistingElfldr())) {
        stage("elfldr not on 127.0.0.1:9021 — run full jailbreak first", "bad");
        return;
    }

    stage("Payload manager ready", "ok");
    showMenu();
}

main().catch(err => {
    const m = (err && err.message) || String(err);
    stage("Failed: " + m, "bad");
    logLine("FATAL: " + m);
});
