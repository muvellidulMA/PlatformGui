#!/usr/bin/env python3
import argparse
import json
import sys
import time

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
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()

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
        print(json.dumps({"type": "ready"}), flush=True)

        while True:
            time.sleep(0.5)
    except Exception as exc:
        print(json.dumps({"type": "error", "error": str(exc)}), flush=True)
        return 1
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
