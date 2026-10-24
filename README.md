# VM Hunter client for Asterisk and VICIdial

An EAGI script that streams the first seconds of a call to [VM Hunter](https://vmhunter.com) and sets `AMDSTATUS` and `AMDCAUSE` on the channel, so your dialplan can connect live people to agents and drop voicemail. It drops straight into a VICIdial routing extension in place of VICIdial's built-in AMD.

Full documentation: https://vmhunter.com/docs/vicidial

## How it works

1. Asterisk answers the call and runs the script with `EAGI`, which gives it the callee's audio on file descriptor 3.
2. The script opens a WebSocket to VM Hunter, sends one config frame with your API key, then streams the audio as 20 ms frames of 8 kHz 16-bit PCM.
3. VM Hunter replies with one JSON verdict, normally about 2.3 seconds after the answer. The script stops streaming the moment it arrives.
4. The script sets three channel variables and exits.

| Variable | Values | Use |
|---|---|---|
| `AMDSTATUS` | `HUMAN` or `MACHINE` | Route on this one. VICIdial's `VD_amd.agi` drops the call when it is `MACHINE`. |
| `AMDSTATUS_RAW` | `HUMAN`, `MACHINE`, `CALLGUARD`, `FAILED` | The server's verdict, untouched. |
| `AMDCAUSE` | `HUMAN`, `MACHINE`, `MACHINE_BEEP`, `MACHINE_STATIC`, `DISCONNECT`, `INITIALSILENCE`, `MAXWORD`, `CALLGUARD_PHRASE:<phrase>`, `AUTH_FAILED`, ... | The reason. `DISCONNECT` means a SIT tone (disconnected number). `CALLGUARD_PHRASE` means call screening (iPhone, Google Call Screen, call blockers). |

The full list of causes is in the [API reference](https://vmhunter.com/docs/api).

## Requirements

- Asterisk with EAGI (VICIdial ships it).
- Python 3 and `websocket-client`: `pip install websocket-client`
- A VM Hunter API key (free tier: 5,000 calls a month, no card): https://vmhunter.com/register

## Install

```bash
cd /var/lib/asterisk/agi-bin
cp -p vmhunter.agi.py vmhunter.agi.py.bak-$(date +%Y%m%d) 2>/dev/null   # if upgrading
wget -O vmhunter.agi.py https://raw.githubusercontent.com/vmhunterhq/vmhunter-asterisk/main/vmhunter.agi.py
chmod +x vmhunter.agi.py
```

The script reads its settings from environment variables, which Asterisk must be able to see. On most installs that is `/etc/environment`; under systemd it is the unit's `Environment=` lines. Restart Asterisk after editing.

```
AMD_WS_API_KEY="your_api_key"
AMD_LOG_FILE="/var/log/vmhunter.agi.log"
```

To confirm Asterisk can see the variable:

```bash
cat /proc/$(pidof asterisk)/environ | tr '\0' '\n' | grep AMD_
```

## Dialplan (VICIdial)

Add this to the context your campaigns use (`/etc/asterisk/extensions.conf`), then `asterisk -rx "dialplan reload"`. Set the campaign's AMD routing extension to `8370`.

```
exten => 8370,1,AGI(agi://127.0.0.1:4577/call_log)
exten => 8370,n,Playback(sip-silence)
exten => 8370,n,EAGI(/var/lib/asterisk/agi-bin/vmhunter.agi.py,${VID})
exten => 8370,n,NoOp(VMHUNTER AMDSTATUS=${AMDSTATUS} RAW=${AMDSTATUS_RAW} CAUSE=${AMDCAUSE})
 ; optional: give disconnected numbers their own disposition so the lead is not recycled
exten => 8370,n,GotoIf($["${AMDCAUSE}"="DISCONNECT"]?disc)
exten => 8370,n,AGI(VD_amd.agi,${EXTEN})
exten => 8370,n,AGI(agi-VDAD_ALL_outbound.agi,NORMAL-----LB-----${CONNECTEDLINE(name)})
exten => 8370,n,Hangup()
exten => 8370,n(disc),AGI(agi-VDAD_ALL_outbound.agi,DISCONNECT-----LB-----${CONNECTEDLINE(name)})
exten => 8370,n,Hangup()
```

Plain Asterisk without VICIdial: replace the two `AGI(...)` lines with your own branch on `${AMDSTATUS}`, for example `GotoIf($["${AMDSTATUS}"="HUMAN"]?agent:hangup)`.

Play silence, not ringback or a prompt, while the script runs. Anything played to the callee delays their greeting and the verdict with it.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `AMD_WS_API_KEY` | (required) | Your API key |
| `AMD_WS_URL` | `wss://app.vmhunter.com/ws` | Server |
| `AMD_AUDIO_SECONDS` | `3.5` | Most audio ever streamed. The server normally answers at about 2.3 s and may listen to 3 s while the callee is still talking. |
| `AMD_CALLGUARD_STATUS` | `HUMAN` | What `AMDSTATUS` to set for call screening: `HUMAN` connects an agent, `MACHINE` drops, `CALLGUARD` passes the raw value through |
| `AMD_FAILED_STATUS` | `MACHINE` | Fail-safe when the server cannot be reached or returns `FAILED` |
| `AMD_LOG_FILE` | (none) | One line per call with the verdict and timings |
| `AMD_DEBUG` | `0` | `1` for verbose logging |

## Call screening

iPhone "Ask Reason for Calling", Google Call Screen and call blockers answer the call with a prompt and a person listens. VM Hunter labels these `AMDCAUSE=CALLGUARD_PHRASE:<phrase>`. `examples/callguard-dialplan.conf` is a routing extension that plays a short recorded intro to the screener and then connects an agent. Check the pre-recorded-message rules for your campaigns before enabling it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every call is `MACHINE` / `INITIALSILENCE` | No audio reaches the script. The extension must use `EAGI`, not `AGI`. |
| `AUTH_FAILED` in the log | Wrong API key, or Asterisk cannot see `AMD_WS_API_KEY`. |
| `WS error: timeout` | The server is unreachable from the dialer. Check outbound TCP to port 2701. |
| Verdicts arrive late | Something is played to the callee before the script runs, or audio is buffered before streaming. |

Every call also appears in your [call logs](https://vmhunter.com/dashboard/call-logs) with the transcript, the reason and the audio the engine heard.

## License

MIT. See `LICENSE`.
