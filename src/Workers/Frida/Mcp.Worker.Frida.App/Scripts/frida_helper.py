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


def list_processes(device):
    items = []
    for proc in device.enumerate_processes():
        items.append({"pid": proc.pid, "name": proc.name})
    return items


def attach(device, pid):
    session = device.attach(pid)
    try:
        return {"attached": True, "pid": pid}
    finally:
        session.detach()


def list_modules(device, pid, timeout_ms):
    session = device.attach(pid)
    try:
        source = (
            "'use strict';"
            "setImmediate(function(){try{"
            "var mods=(typeof Process.enumerateModulesSync==='function') ? Process.enumerateModulesSync() : Process.enumerateModules();"
            "var list=mods.map(function(m){return {name:m.name, base:m.base.toString(), size:m.size, path:m.path};});"
            "send({data:list});"
            "}catch(e){send({error:e.message});}});"
        )
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


def list_exports(device, pid, module_name, timeout_ms):
    session = device.attach(pid)
    try:
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
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


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


def read_memory(device, pid, address, size, timeout_ms):
    session = device.attach(pid)
    try:
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
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


def read_string(device, pid, address, max_length, encoding, timeout_ms):
    session = device.attach(pid)
    try:
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
            f"var addr=ptr({addr_json});var maxLen={max_length};var enc={encoding_json};"
            "var res=null;"
            "if(enc==='utf16' || enc==='utf-16'){res=readUtf16(addr,maxLen);send({data:res.text,encoding:'utf16',bytesRead:res.bytes,terminated:res.terminated});}"
            "else if(enc==='ascii'){res=readAscii(addr,maxLen);send({data:res.text,encoding:'ascii',bytesRead:res.bytes,terminated:res.terminated});}"
            "else {res=readUtf8(addr,maxLen);send({data:res.text,encoding:'utf8',bytesRead:res.bytes,terminated:res.terminated});}"
            "}catch(e){send({error:e.message});}});"
        )
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


def scan_memory(device, pid, address, size, pattern, timeout_ms):
    session = device.attach(pid)
    try:
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
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


def write_memory(device, pid, address, hex_data, timeout_ms):
    session = device.attach(pid)
    try:
        addr_json = json.dumps(address)
        hex_json = json.dumps(hex_data)
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
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()


def call_function(device, pid, address, ret_type, arg_types, args, timeout_ms):
    session = device.attach(pid)
    try:
        addr_json = json.dumps(address)
        ret_json = json.dumps(ret_type)
        arg_types_json = json.dumps(arg_types)
        args_json = json.dumps(args)
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
        payload = run_script(session, source, timeout_ms)
        if payload and payload.get("error"):
            raise RuntimeError(payload.get("error"))
        return payload
    finally:
        session.detach()

def spawn_process(device, program, args):
    argv = [program]
    if args:
        argv.extend(args)
    pid = device.spawn(argv)
    return {"pid": pid, "argv": argv}


def resume_process(device, pid):
    device.resume(pid)
    return {"pid": pid, "resumed": True}


def kill_process(device, pid):
    device.kill(pid)
    return {"pid": pid, "killed": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--op", required=True)
    parser.add_argument("--device", default="local")
    parser.add_argument("--remote-host")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--program")
    parser.add_argument("--args")
    parser.add_argument("--module")
    parser.add_argument("--address")
    parser.add_argument("--size", type=int, default=0)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--encoding", default="utf8")
    parser.add_argument("--pattern")
    parser.add_argument("--data-hex")
    parser.add_argument("--ret-type")
    parser.add_argument("--arg-types")
    parser.add_argument("--arg-values")
    parser.add_argument("--timeout-ms", type=int, default=5000)
    args = parser.parse_args()

    try:
        device = get_device(args)
        if args.op == "list_processes":
            data = list_processes(device)
        elif args.op == "attach":
            if args.pid is None:
                raise RuntimeError("pid gerekli")
            data = attach(device, args.pid)
        elif args.op == "list_modules":
            if args.pid is None:
                raise RuntimeError("pid gerekli")
            data = list_modules(device, args.pid, args.timeout_ms)
        elif args.op == "list_exports":
            if args.pid is None or not args.module:
                raise RuntimeError("pid ve module gerekli")
            data = list_exports(device, args.pid, args.module, args.timeout_ms)
        elif args.op == "read_memory":
            if args.pid is None or not args.address or args.size <= 0:
                raise RuntimeError("pid/address/size gerekli")
            data = read_memory(device, args.pid, args.address, args.size, args.timeout_ms)
        elif args.op == "read_string":
            if args.pid is None or not args.address:
                raise RuntimeError("pid/address gerekli")
            data = read_string(
                device, args.pid, args.address, args.max_length, args.encoding, args.timeout_ms
            )
        elif args.op == "scan_memory":
            if args.pid is None or not args.address or args.size <= 0 or not args.pattern:
                raise RuntimeError("pid/address/size/pattern gerekli")
            data = scan_memory(device, args.pid, args.address, args.size, args.pattern, args.timeout_ms)
        elif args.op == "write_memory":
            if args.pid is None or not args.address or not args.data_hex:
                raise RuntimeError("pid/address/data gerekli")
            data = write_memory(device, args.pid, args.address, args.data_hex, args.timeout_ms)
        elif args.op == "call_function":
            if args.pid is None or not args.address or not args.arg_types or not args.arg_values:
                raise RuntimeError("pid/address/args gerekli")
            ret_type = args.ret_type or "pointer"
            arg_types = json.loads(args.arg_types)
            arg_values = json.loads(args.arg_values)
            data = call_function(device, args.pid, args.address, ret_type, arg_types, arg_values, args.timeout_ms)
        elif args.op == "spawn":
            if not args.program:
                raise RuntimeError("program gerekli")
            argv = []
            if args.args:
                try:
                    argv = json.loads(args.args)
                except Exception as exc:
                    raise RuntimeError(f"args json gecersiz: {exc}")
            data = spawn_process(device, args.program, argv)
        elif args.op == "resume":
            if args.pid is None:
                raise RuntimeError("pid gerekli")
            data = resume_process(device, args.pid)
        elif args.op == "kill":
            if args.pid is None:
                raise RuntimeError("pid gerekli")
            data = kill_process(device, args.pid)
        else:
            raise RuntimeError("bilinmeyen op")

        print(json.dumps({"ok": True, "data": data}))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
