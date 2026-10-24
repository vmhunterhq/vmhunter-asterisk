#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
(Asterisk EAGI client — UPGRADED-server compatible)

- Reads audio from EAGI fd=3 (PCM s16le mono)
- Connects to WS server
- Sends audio chunks for first N seconds (controlled by server MAX_AUDIO_SEC too)
- Receives ONLY JSON response {"AMDSTATUS":"...","AMDCAUSE":"..."} and sets Asterisk vars

Upgraded-server verdicts this client understands:
  AMDSTATUS : HUMAN | MACHINE | CALLGUARD | FAILED
  AMDCAUSE  : HUMAN | MACHINE | MACHINE_BEEP | DISCONNECT | MACHINE_STATIC |
              INITIALSILENCE | MAXWORD | CALLGUARD_PHRASE:<...>
It maps them to a VICIdial-safe AMDSTATUS (HUMAN/MACHINE), preserves the granular
reason in AMDCAUSE, and exposes the untouched server verdict in AMDSTATUS_RAW.
Backward-compatible: the base server only ever returns HUMAN/MACHINE, which map
1:1, so this client is safe against both the base (:2701) and upgraded servers.

Install:
  pip install websocket-client

ENV:
  export AMD_WS_URL="wss://app.vmhunter.com/ws"
  export AMD_WS_API_KEY="{YOUR_API_KEY}"
  export AMD_AUDIO_SECONDS="3.5"   # MAXIMUM streamed; the server normally answers at ~2.3 s
                                   # and may listen up to 3 s while the callee is still talking
  export AMD_SAMPLE_RATE="8000"
  export AMD_CHUNK_MS="20"
  export AMD_LOG_FILE="/var/log/vmhunter.agi.log"
  export AMD_DEBUG="0"
  # How to route the two non-native statuses in VICIdial:
  export AMD_CALLGUARD_STATUS="HUMAN"    # HUMAN=connect (default) | MACHINE=drop | CALLGUARD=passthrough
  export AMD_FAILED_STATUS="MACHINE"     # fail-safe when the server errors

Dialplan example (branch on the new verdicts BEFORE VD_amd.agi):
exten => 8370,1,AGI(agi://127.0.0.1:4577/call_log)
exten => 8370,n,Playback(sip-silence)
exten => 8370,n,EAGI(/var/lib/asterisk/agi-bin/vmhunter.agi.py,${VID})
exten => 8370,n,NoOp(AMDSTATUS=${AMDSTATUS} RAW=${AMDSTATUS_RAW} CAUSE=${AMDCAUSE})
 ; optional: give disconnected numbers their own disposition (do not recycle the lead)
exten => 8370,n,GotoIf($["${AMDCAUSE}"="DISCONNECT"]?disc)
 ; optional: send screened calls straight to an agent (already HUMAN by default)
exten => 8370,n,GotoIf($["${AMDSTATUS_RAW}"="CALLGUARD"]?human)
exten => 8370,n,AGI(VD_amd.agi,${EXTEN})
exten => 8370,n(human),AGI(agi-VDAD_ALL_outbound.agi,NORMAL-----LB-----${CONNECTEDLINE(name)})
exten => 8370,n,Hangup()
exten => 8370,n(disc),AGI(agi-VDAD_ALL_outbound.agi,DISCONNECT-----LB-----${CONNECTEDLINE(name)})
exten => 8370,n,Hangup()
"""

import os
import sys
import json
import time
import select
import logging
from websocket import create_connection

AMD_WS_URL = os.getenv("AMD_WS_URL", "wss://app.vmhunter.com/ws").strip()  # TLS; ws://app.vmhunter.com:2701 is the unencrypted fallback
AMD_WS_API_KEY = os.getenv("AMD_WS_API_KEY", "").strip()
AUDIO_SECONDS = float(os.getenv("AMD_AUDIO_SECONDS", "3.5"))   # upper bound, see below
SAMPLE_RATE = int(os.getenv("AMD_SAMPLE_RATE", "8000"))
CHUNK_MS = int(os.getenv("AMD_CHUNK_MS", "20"))
DEBUG = os.getenv("AMD_DEBUG", "0") == "1"
LOG_FILE = os.getenv("AMD_LOG_FILE", "/var/log/vmhunter.agi.log")

# --- Upgraded-server verdict mapping ------------------------------------------
# The upgraded WS server can return AMDSTATUS in {HUMAN, MACHINE, CALLGUARD,
# FAILED}. All the fine-grained machine reasons (MACHINE_BEEP, DISCONNECT,
# MACHINE_STATIC, INITIALSILENCE, MAXWORD) come back inside AMDCAUSE while
# AMDSTATUS stays "MACHINE", so VD_amd.agi (which drops on AMDSTATUS=="MACHINE")
# already handles them correctly.
#
# The two statuses VICIdial does NOT natively understand are mapped here:
#   CALLGUARD  = call-screening / "who's calling?" -> usually a real person.
#                Default HUMAN so VD_amd.agi routes it to an agent (do NOT drop).
#                Set AMD_CALLGUARD_STATUS=MACHINE to drop it, or =CALLGUARD to
#                pass it through untouched for a custom dialplan branch.
#   FAILED     = auth/subscription/DB error on the server (AMD did not run).
#                Default MACHINE (fail-safe, matches the original client).
CALLGUARD_STATUS = os.getenv("AMD_CALLGUARD_STATUS", "HUMAN").strip().upper()
FAILED_STATUS = os.getenv("AMD_FAILED_STATUS", "MACHINE").strip().upper()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE)],
)
log = logging.getLogger("vmhunter-amd-client")


def agi_write(line: str) -> None:
    sys.stdout.write(line.rstrip() + "\n")
    sys.stdout.flush()


def agi_read_line() -> str:
    return sys.stdin.readline().strip()


def agi_setvar(k: str, v: str) -> None:
    agi_write(f'SET VARIABLE {k} "{(v or "")}"')


def agi_verbose(msg: str, level: int = 1) -> None:
    agi_write(f'VERBOSE "{msg}" {level}')


def read_agi_env():
    env = {}
    while True:
        line = agi_read_line()
        if line == "":
            break
        if ":" in line:
            k, v = line.split(":", 1)
            env[k.strip()] = v.strip()
    return env


def main():
    agi_setvar("AMDSTATUS", "MACHINE")
    agi_setvar("AMDCAUSE", "MACHINE")

    env = read_agi_env()

    # ONLY VID from calleridname
    vid = (env.get("agi_calleridname", "") or "").strip() or "UNKNOWN"
    ani = env.get("agi_callerid", "") or "UNKNOWN"
    uniqueid = env.get("agi_uniqueid", "") or "UNKNOWN"

    if not AMD_WS_URL:
        agi_setvar("AMDSTATUS", "MACHINE")
        agi_setvar("AMDCAUSE", "MACHINE")
        agi_verbose("AMD_WS_URL not set", 1)
        return

    if not AMD_WS_API_KEY:
        agi_setvar("AMDSTATUS", "MACHINE")
        agi_setvar("AMDCAUSE", "MACHINE")
        agi_verbose("AMD_WS_API_KEY not set", 1)
        return

    tag = f"vid={vid}"
    agi_verbose(f"AMD WS client start ({tag})", 1)

    try:
        audio_fd = os.fdopen(3, "rb", buffering=0)  # EAGI fd=3
    except Exception as e:
        agi_verbose(f"ERROR opening EAGI fd=3: {type(e).__name__}", 1)
        return

    bytes_per_sample = 2
    bytes_per_chunk = int(SAMPLE_RATE * (CHUNK_MS / 1000.0) * bytes_per_sample)
    max_bytes = int(SAMPLE_RATE * bytes_per_sample * AUDIO_SECONDS)

    ws = None
    try:
        ws = create_connection(AMD_WS_URL, timeout=3)

        # Send ONLY vid + api_key (sr/bps optional but useful)
        ws.send(json.dumps({
            "config": {
                "vid": vid,
                "ani": ani,
                "uniqueid": uniqueid,
                "api_key": AMD_WS_API_KEY,
                "sample_rate": SAMPLE_RATE,
                "bytes_per_sample": bytes_per_sample,
            }
        }))

        sent = 0
        t0 = time.time()

        # Stream until the server answers (normally after ~2 s of audio) or until
        # AUDIO_SECONDS as a safety cap. The server decides when it has heard
        # enough — it may keep listening past 2 s while the callee is still
        # mid-sentence — so do not stop at a fixed 2 s and send eof: that would
        # force the decision early. The reply is detected with a zero-timeout
        # select on the socket between chunks.
        replied = False
        while sent < max_bytes:
            chunk = audio_fd.read(bytes_per_chunk)
            if not chunk:
                break
            ws.send_binary(chunk)
            sent += len(chunk)

            try:
                readable, _, _ = select.select([ws.sock], [], [], 0)
            except Exception:
                readable = []
            if readable:
                replied = True
                break

            if (time.time() - t0) >= (AUDIO_SECONDS + 0.25):
                break

        if not replied:
            try:
                ws.send(json.dumps({"eof": 1}))
            except Exception:
                pass

        resp_raw = ws.recv()
        try:
            resp = json.loads(resp_raw)
        except Exception:
            resp = {}

        raw_status = str(resp.get("AMDSTATUS", "MACHINE")).upper().strip() or "MACHINE"
        # Keep the fine-grained cause (BEEP/DISCONNECT/STATIC/INITIALSILENCE/
        # MAXWORD/CALLGUARD_*). Fall back to the status if the server omits it.
        raw_cause = str(resp.get("AMDCAUSE", "")).upper().strip() or raw_status

        # Map the server verdict to a VICIdial-facing AMDSTATUS. VD_amd.agi drops
        # only when AMDSTATUS == "MACHINE"; every other value routes to an agent.
        if raw_status == "HUMAN":
            vd_status = "HUMAN"
        elif raw_status == "MACHINE":
            vd_status = "MACHINE"          # incl. BEEP/DISCONNECT/STATIC/INITIALSILENCE/MAXWORD
        elif raw_status == "CALLGUARD":
            vd_status = CALLGUARD_STATUS    # default HUMAN -> connect to agent
        elif raw_status == "FAILED":
            vd_status = FAILED_STATUS       # default MACHINE -> fail-safe
        else:
            vd_status = "MACHINE"           # unknown status -> safe default

        # AMDSTATUS_RAW preserves the server's original verdict so the dialplan
        # can still branch on CALLGUARD / DISCONNECT / etc. without affecting the
        # VD_amd.agi HUMAN/MACHINE decision.
        agi_setvar("AMDSTATUS", vd_status)
        agi_setvar("AMDCAUSE", raw_cause)
        agi_setvar("AMDSTATUS_RAW", raw_status)
        agi_verbose(
            f"AMD FINAL via WS: raw={raw_status} -> vd={vd_status} cause={raw_cause}", 1
        )

    except Exception as e:
        log.warning(f"[{tag}] WS error: {type(e).__name__}: {e}")
        agi_setvar("AMDSTATUS", "MACHINE")
        agi_setvar("AMDCAUSE", "MACHINE")
    finally:
        try:
            if ws:
                ws.close()
        except Exception:
            pass
        try:
            audio_fd.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()