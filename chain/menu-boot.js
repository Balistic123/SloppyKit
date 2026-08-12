import { establishPrimitive, fakeCellReleased } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";

const Q = new URLSearchParams(location.search);
const ARMED = Q.get("go") === "1";
const BUILD = () => window.P2JB_BUILD || "dev";
const MAX_ATTEMPTS = Math.max(1, Math.min(48,
    parseInt(Q.get("attempts") || "12", 10)));

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

function trimMemory() {
    try {
        logEl.textContent = logEl.textContent.slice(-2000);
        if (typeof globalThis.gc === "function") {
            globalThis.gc();
            globalThis.gc();
            globalThis.gc();
        }
    } catch (e) { }
}

async function settleMemory(ms) {
    await new Promise(r => setTimeout(r, ms));
    trimMemory();
    await new Promise(r => setTimeout(r, 250));
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
    logLine("loading chain scripts…");
    await loadScript("main.js?b=" + B);
    window.offsetsReady = waitOffsetsReady();
    await loadScript("rop.js?b=" + B);
    await loadScript("syscalls.js?b=" + B);
    await window.offsetsReady;
    logLine("chain scripts ready");
}

function classify(raw) {
    const s32 = ((raw.low << 0) >> 0);
    const failed = s32 < 0;
    return { s32, failed };
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
        hex: "0x" + raw.toString(), errText: errText({ failed: cl.failed, s32: cl.s32, hex: "0x" + raw.toString() }) };
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

async function bootWebKit() {
    stage("WebKit exploit — attempt 1…");
    try { history.replaceState(null, ""); } catch (e) { }
    if (typeof globalThis.gc === "function") try { globalThis.gc(); } catch (e) { }
    await new Promise(r => setTimeout(r, 500));

    const carrier = await establishPrimitive({
        maxAttempts: MAX_ATTEMPTS,
        onEvent(tag, detail, attempt) {
            if (tag === "ATTEMPT-START")
                stage("WebKit exploit — attempt " + attempt + "…");
        }
    });
    if (!Number.isFinite(carrier.homeVector))
        throw new Error("bad carrier homeVector");

    installWindowP(carrier, { onEvent() { } });
    if (!pairStatus.promoted)
        throw new Error("pair not promoted: " + pairStatus.error);
    logLine("primitive up, released=" + fakeCellReleased());
    await settleMemory(1200);
}

async function bootPrepare() {
    const p = globalThis.p;
    if (!p || typeof p.read8 !== "function")
        throw new Error("window.p missing");

    stage("prepare() — lite stack");
    logLine("prepare() starting");
    const prepared = await prepare(p, {
        stackSize: 0x18000,
        reservedStack: 0x3000
    });
    P = prepared.p;
    chain = prepared.chain;
    logLine("prepare() ok, pid syscall passed");
    await settleMemory(1500);
    trimMemory();
}

async function main() {
    if (!ARMED) {
        stage("Add ?go=1 to the URL or use the index page button.");
        return;
    }

    document.getElementById("buildTag").textContent = "Build " + BUILD() + " (menu lite)";
    logLine("menu-lite boot build=" + BUILD());

    await bootWebKit();
    await loadChainScripts();
    await bootPrepare();

    stage("Checking elfldr on 127.0.0.1:9021…");
    if (!(await probeExistingElfldr())) {
        stage("elfldr not found on 127.0.0.1:9021 — run full jailbreak first", "bad");
        logLine("elfldr probe failed");
        return;
    }

    logLine("elfldr reachable");
    stage("Payload manager ready", "ok");
    showMenu();
}

main().catch(err => {
    const m = (err && err.message) || String(err);
    stage("Failed: " + m, "bad");
    logLine("FATAL: " + m);
});
