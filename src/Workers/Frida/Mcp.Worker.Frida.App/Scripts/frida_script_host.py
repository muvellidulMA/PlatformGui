#!/usr/bin/env python3
import argparse
import json
import sys

import frida


def get_device(args):
    if args.device == "usb":
        return frida.get_usb_device(timeout=args.timeout_ms)
    if args.device == "remote":
        return frida.get_remote_device(timeout=args.timeout_ms)
    if args.device == "host":
        if not args.remote_host:
            raise RuntimeError("remote_host gerekli")
        return frida.get_device_manager().add_remote_device(args.remote_host)
    return frida.get_local_device()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--device", default="local")
    parser.add_argument("--remote-host")
    parser.add_argument("--script", required=True)
    parser.add_argument("--script-id", required=True)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()

    session = None
    script = None

    try:
        device = get_device(args)
        session = device.attach(args.pid)
        with open(args.script, "r", encoding="utf-8") as fh:
            source = fh.read()

        script = session.create_script(source)

        def on_message(message, data):
            payload = {
                "type": message.get("type"),
                "payload": message.get("payload"),
                "description": message.get("description"),
                "stack": message.get("stack"),
            }
            print(json.dumps(payload), flush=True)

        script.on("message", on_message)
        script.load()
        print(json.dumps({"type": "ready", "scriptId": args.script_id}), flush=True)

        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            try:
                cmd = json.loads(line)
            except Exception as exc:
                print(json.dumps({"type": "error", "error": str(exc)}), flush=True)
                continue

            op = cmd.get("op")
            if op == "rpc":
                req_id = cmd.get("id")
                method = cmd.get("method")
                args_list = cmd.get("args") or []
                try:
                    exports = getattr(script, "exports_sync", None)
                    if exports is None:
                        exports = script.exports
                    func = getattr(exports, method)
                    result = func(*args_list)
                    print(json.dumps({"type": "rpc_response", "id": req_id, "ok": True, "result": result}), flush=True)
                except Exception as exc:
                    print(json.dumps({"type": "rpc_response", "id": req_id, "ok": False, "error": str(exc)}), flush=True)
            elif op == "post":
                payload = cmd.get("payload")
                try:
                    script.post(payload)
                    print(json.dumps({"type": "post_ack"}), flush=True)
                except Exception as exc:
                    print(json.dumps({"type": "post_error", "error": str(exc)}), flush=True)
            elif op == "unload":
                try:
                    script.unload()
                except Exception:
                    pass
                try:
                    session.detach()
                except Exception:
                    pass
                print(json.dumps({"type": "unloaded"}), flush=True)
                return 0
            else:
                print(json.dumps({"type": "error", "error": "unknown op"}), flush=True)
    except Exception as exc:
        print(json.dumps({"type": "error", "error": str(exc)}), flush=True)
        return 1
    finally:
        try:
            if script is not None:
                script.unload()
        except Exception:
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
