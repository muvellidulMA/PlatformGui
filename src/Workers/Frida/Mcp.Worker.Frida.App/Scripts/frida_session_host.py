#!/usr/bin/env python3
import argparse
import json
import sys
import threading

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


def send_response(req_id, ok, data=None, error=None):
    payload = {"type": "response", "id": req_id, "ok": ok}
    if ok:
        payload["data"] = data
    else:
        payload["error"] = error
    print(json.dumps(payload), flush=True)


def send_event(name, payload=None):
    msg = {"type": "event", "name": name}
    if payload is not None:
        msg["payload"] = payload
    print(json.dumps(msg), flush=True)


def run_script(session, source, timeout_ms):
    done = threading.Event()
    result = {"payload": None, "error": None}

    def on_message(message, data):
        if message.get("type") == "send":
            result["payload"] = message.get("payload")
        elif message.get("type") == "error":
            result["error"] = message.get("stack") or message.get("description")
        done.set()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    if not done.wait(timeout_ms / 1000.0):
        script.unload()
        raise RuntimeError("script timeout")
    script.unload()
    if result["error"]:
        raise RuntimeError(result["error"])
    return result["payload"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--device", default="local")
    parser.add_argument("--remote-host")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()

    session = None

    def on_detached(reason, crash):
        send_event("detached", {"reason": reason, "crash": crash})

    try:
        device = get_device(args)
        session = device.attach(args.pid)
        session.on("detached", on_detached)
        send_event("ready", {"pid": args.pid, "sessionId": args.session_id})

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
                send_response("unknown", False, error=str(exc))
                continue

            req_id = cmd.get("id") or "unknown"
            op = cmd.get("op")
            params = cmd.get("args") or {}

            try:
                if op == "list_modules":
                    source = (
                        "'use strict';"
                        "setImmediate(function(){try{"
                        "var mods=(typeof Process.enumerateModulesSync==='function') ? Process.enumerateModulesSync() : Process.enumerateModules();"
                        "var list=mods.map(function(m){return {name:m.name, base:m.base.toString(), size:m.size, path:m.path};});"
                        "send({data:list});"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "list_exports":
                    module_name = params.get("module")
                    if not module_name:
                        raise RuntimeError("module gerekli")
                    module_json = json.dumps(module_name)
                    source = (
                        "'use strict';"
                        "setImmediate(function(){try{"
                        f"var name={module_json};"
                        "function sendList(list){send({data:list.map(function(e){return {name:e.name, address:e.address.toString(), type:e.type};})});}"
                        "var module=Process.getModuleByName(name);"
                        "if(!module){throw new Error('module not found');}"
                        "if(typeof module.enumerateExportsSync==='function'){"
                        "  var exports=module.enumerateExportsSync();"
                        "  sendList(exports);"
                        "} else if (typeof module.enumerateExports==='function') {"
                        "  if (module.enumerateExports.length >= 1) {"
                        "    var list=[];"
                        "    module.enumerateExports({"
                        "      onMatch:function(e){list.push(e);},"
                        "      onComplete:function(){sendList(list);}"
                        "    });"
                        "  } else {"
                        "    var res=module.enumerateExports();"
                        "    Promise.resolve(res).then(function(exports){sendList(exports);}).catch(function(err){send({error:err.message});});"
                        "  }"
                        "} else {"
                        "  throw new Error('module exports not supported');"
                        "}"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "read_memory":
                    address = params.get("address")
                    size = int(params.get("size") or 0)
                    if not address or size <= 0:
                        raise RuntimeError("address/size gerekli")
                    addr_json = json.dumps(address)
                    source = (
                        "'use strict';"
                        "function toHexFromBytes(list){var h='';for(var i=0;i<list.length;i++){var b=list[i].toString(16);if(b.length<2)b='0'+b;h+=b;}return h;}"
                        "function readBytes(addr,size){"
                        "  var list=[];"
                        "  for(var i=0;i<size;i++){list.push(addr.add(i).readU8());}"
                        "  return list;"
                        "}"
                        "setImmediate(function(){try{"
                        f"var addr=ptr({addr_json});var size={size};"
                        "var bytes=readBytes(addr,size);"
                        "send({data:toHexFromBytes(bytes),size:size});"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "read_string":
                    address = params.get("address")
                    max_len = int(params.get("maxLength") or params.get("max_length") or 256)
                    encoding = params.get("encoding") or "utf8"
                    if not address:
                        raise RuntimeError("address gerekli")
                    addr_json = json.dumps(address)
                    encoding_json = json.dumps(encoding)
                    source = (
                        "'use strict';"
                        "function readAscii(addr,maxLen){"
                        "  var bytes=[];var terminated=false;"
                        "  for(var i=0;i<maxLen;i++){var b=addr.add(i).readU8();if(b===0){terminated=true;break;}bytes.push(b);}"
                        "  var s='';for(var i=0;i<bytes.length;i++){s+=String.fromCharCode(bytes[i]);}"
                        "  return {text:s,bytes:bytes.length,terminated:terminated};"
                        "}"
                        "function readUtf8(addr,maxLen){"
                        "  var bytes=[];var terminated=false;"
                        "  for(var i=0;i<maxLen;i++){var b=addr.add(i).readU8();if(b===0){terminated=true;break;}bytes.push(b);}"
                        "  var s='';"
                        "  if(typeof TextDecoder==='function'){s=new TextDecoder('utf-8').decode(Uint8Array.from(bytes));}"
                        "  else {for(var i=0;i<bytes.length;i++){s+=String.fromCharCode(bytes[i]);}}"
                        "  return {text:s,bytes:bytes.length,terminated:terminated};"
                        "}"
                        "function readUtf16(addr,maxLen){"
                        "  var s='';var terminated=false;var count=0;"
                        "  for(var i=0;i<maxLen;i++){var code=addr.add(i*2).readU16();if(code===0){terminated=true;break;}s+=String.fromCharCode(code);count++;}"
                        "  return {text:s,bytes:count*2,terminated:terminated};"
                        "}"
                        "setImmediate(function(){try{"
                        f"var addr=ptr({addr_json});var maxLen={max_len};var enc={encoding_json};"
                        "var res=null;"
                        "if(enc==='utf16' || enc==='utf-16'){res=readUtf16(addr,maxLen);send({data:res.text,encoding:'utf16',bytesRead:res.bytes,terminated:res.terminated});}"
                        "else if(enc==='ascii'){res=readAscii(addr,maxLen);send({data:res.text,encoding:'ascii',bytesRead:res.bytes,terminated:res.terminated});}"
                        "else {res=readUtf8(addr,maxLen);send({data:res.text,encoding:'utf8',bytesRead:res.bytes,terminated:res.terminated});}"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "scan_memory":
                    address = params.get("address")
                    size = int(params.get("size") or 0)
                    pattern = params.get("pattern")
                    if not address or size <= 0 or not pattern:
                        raise RuntimeError("address/size/pattern gerekli")
                    addr_json = json.dumps(address)
                    pattern_json = json.dumps(pattern)
                    source = (
                        "'use strict';"
                        "setImmediate(function(){try{"
                        f"var addr=ptr({addr_json});var size={size};var pat={pattern_json};"
                        "var res=Memory.scanSync(addr,size,pat);"
                        "var list=res.map(function(r){return r.address.toString();});"
                        "send({data:list});"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "write_memory":
                    address = params.get("address")
                    data_hex = params.get("dataHex") or params.get("data")
                    if not address or not data_hex:
                        raise RuntimeError("address/dataHex gerekli")
                    addr_json = json.dumps(address)
                    hex_json = json.dumps(data_hex)
                    source = (
                        "'use strict';"
                        "function hexToBytes(hex){"
                        "  var clean=String(hex).replace(/[^0-9a-fA-F]/g,'');"
                        "  var out=[];"
                        "  for(var i=0;i<clean.length;i+=2){out.push(parseInt(clean.substr(i,2),16));}"
                        "  return out;"
                        "}"
                        "setImmediate(function(){try{"
                        f"var addr=ptr({addr_json});var hex={hex_json};"
                        "var bytes=hexToBytes(hex);"
                        "if (typeof Memory !== 'undefined' && typeof Memory.writeByteArray === 'function') {"
                        "  Memory.writeByteArray(addr, bytes);"
                        "} else if (typeof addr.writeByteArray === 'function') {"
                        "  addr.writeByteArray(bytes);"
                        "} else {"
                        "  for (var i = 0; i < bytes.length; i++) { addr.add(i).writeU8(bytes[i]); }"
                        "}"
                        "send({data:{written:bytes.length}});"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "call_function":
                    address = params.get("address")
                    ret_type = params.get("returnType") or "pointer"
                    arg_types = params.get("argTypes") or []
                    arg_values = params.get("argValues") or []
                    if not address:
                        raise RuntimeError("address gerekli")
                    addr_json = json.dumps(address)
                    ret_json = json.dumps(ret_type)
                    arg_types_json = json.dumps(arg_types)
                    args_json = json.dumps(arg_values)
                    source = (
                        "'use strict';"
                        "function toArg(val, type){"
                        "  if(type==='pointer'){return ptr(val);}"
                        "  if(type==='int'){return parseInt(val);} "
                        "  if(type==='int64'){"
                        "    if(typeof int64==='function'){return int64(val);} "
                        "    if(typeof Int64==='function'){return new Int64(val);} "
                        "    return ptr(val);"
                        "  }"
                        "  if(type==='uint64'){"
                        "    if(typeof uint64==='function'){return uint64(val);} "
                        "    if(typeof UInt64==='function'){return new UInt64(val);} "
                        "    return ptr(val);"
                        "  }"
                        "  if(type==='uint32'){return parseInt(val)>>>0;} "
                        "  return ptr(val);"
                        "}"
                        "setImmediate(function(){try{"
                        f"var addr=ptr({addr_json});"
                        f"var retType={ret_json};"
                        f"var argTypes={arg_types_json};"
                        f"var argValues={args_json};"
                        "var fn=new NativeFunction(addr, retType, argTypes);"
                        "var jsArgs=[];"
                        "for(var i=0;i<argTypes.length;i++){jsArgs.push(toArg(argValues[i], argTypes[i]));}"
                        "var res=fn.apply(null, jsArgs);"
                        "if(res===undefined || res===null){"
                        "  send({data:{result:null}});"
                        "}else if(typeof res==='object' && typeof res.toString==='function'){"
                        "  send({data:{result:res.toString()}});"
                        "}else{"
                        "  send({data:{result:String(res)}});"
                        "}"
                        "}catch(e){send({error:e.message});}});"
                    )
                    payload = run_script(session, source, args.timeout_ms)
                    if payload and payload.get("error"):
                        raise RuntimeError(payload.get("error"))
                    send_response(req_id, True, payload)
                elif op == "detach":
                    try:
                        session.detach()
                    except Exception:
                        pass
                    send_response(req_id, True, {"data": {"detached": True}})
                    return 0
                else:
                    raise RuntimeError("bilinmeyen op")
            except Exception as exc:
                send_response(req_id, False, error=str(exc))
    except Exception as exc:
        send_event("error", {"error": str(exc)})
        return 1
    finally:
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
