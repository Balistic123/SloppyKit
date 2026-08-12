# P2JB WebKit

Standalone PS5 browser jailbreak host: **Slopkit WebKit userland** chained to the **P2JB** kernel exploit (`kqueueex` / `cr_ref` overflow).

Supports retail firmware **9.00 – 12.70** (kernel offsets alias to 12.00/12.40 buckets).

This folder is independent from `slopkit/` (Poops fast path). It only ships the long P2JB chain.

## Layout

```
slopkit-p2jb/
  index.html          Landing page
  host.py             Local HTTPS server (port 8888)
  chain/              Exploit chain (WebKit + kernel)
    p2jb.html         Main exploit page
    p2jb-kernel.js    P2JB kernel stages
    core.js           WebKit bug (Slopkit)
    main.js           ROP / offset loader
  offsets/            Per-firmware gadget tables
  payloads/           kexp + elfldr + optional servers
  ui/                 Post-jailbreak payload menu tiles
```

## Quick start (local host)

1. Place `localhost.pem` next to `host.py` (TLS cert for PS5 browser).
2. From this directory:

   ```powershell
   python host.py
   ```

3. Point the PS5 browser at `https://<your-pc-ip>:8888/index.html`
   (User's Guide trick, DNS redirect, or a Web Shortcut).

4. Click **START JAILBREAK** and leave the page open ~50 minutes.

5. When complete, send ELFs to `127.0.0.1:9021` on the console.

## Direct URL

```
chain/p2jb.html?go=1&auto=1&trigger=overflow&burn=full&payload=1
```

## Credits

- Slopkit WebKit exploit — Jordy / scene
- P2JB kernel exploit — Gezine / cheburek3000
- Y2JB port reference — matem6
- WebKit kernel chain in browser — slopkit `poops.js` lineage (repurposed here as `p2jb-kernel.js`)

## Notes

- **One attempt per boot** after the irreversible `setuid(1)` prep stage.
- **12.40+** uses `offsets/12.40.js` (libkernel export deltas vs 12.00).
- Keep the browser tab open until payloads finish loading.
