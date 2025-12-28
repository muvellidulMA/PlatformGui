# MCP Gateway (net9)

Bu klasor, MCP Gateway ve worker iskeletini barindirir.

## Calistirma

Gateway (SSE):
```
dotnet run --project src/Gateway/Mcp.Gateway.App
```

STDIO modu:
```
dotnet run --project src/Gateway/Mcp.Gateway.App -- --stdio --no-http
```

Fake worker:
```
dotnet run --project src/Workers/Fake/Mcp.Worker.Fake.App
```

Frida worker:
```
dotnet run --project src/Workers/Frida/Mcp.Worker.Frida.App
```

WPF GUI (Windows):
```
dotnet run --project src/Gui/Mcp.Platform.Gui
```

## Ayarlar

`src/Gateway/Mcp.Gateway.App/appsettings.json`:
- `Gateway:AuthToken` varsayilan `CHANGE_ME`, calistirmadan once degistirin.
- `Gateway:Http:Url` varsayilan `http://0.0.0.0:13338`.
- `Workers` listesi worker adreslerini tutar.

`src/Workers/Frida/Mcp.Worker.Frida.App/appsettings.json`:
- `FridaPsPath` frida-ps yolunu belirtir.
- `Device` (local/usb/remote/host) secimi yapar.
- `ReadMemoryScriptPath` bos ise read_memory error doner.
- `ListMode` (default/apps/all) listeleme modunu belirler. `default`/`all` flag eklemez, `apps` icin `-a` kullanir.
- `PythonPath` frida helper icin python yolunu belirtir.
- `PythonArgs` python argumanlarini listeler (ornegin `["-3"]`).
- `HelperScriptPath` bos ise `Scripts/frida_helper.py` kullanilir.
- `HookerScriptPath` bos ise `Scripts/frida_hooker.py` kullanilir.
- `ScriptHostPath` bos ise `Scripts/frida_script_host.py` kullanilir.
- `BlockedTools` istenmeyen araclari engeller.

## Frida Araclari

- Gateway `ToolPrefix` varsayilan olarak `frida_` oldugu icin istemci tarafinda tool adlari `frida_*` seklindedir.

- `frida_list_processes`
- `frida_spawn`
- `frida_resume`
- `frida_kill`
- `frida_attach`
- `frida_list_modules`
- `frida_list_exports`
- `frida_read_memory`
- `frida_read_string`
- `frida_scan_memory`
- `frida_write_memory`
- `frida_call_function`
- `frida_hook_start`
- `frida_hook_poll`
- `frida_hook_stop`
- `frida_set_breakpoint`
- `frida_script_load`
- `frida_script_unload`
- `frida_script_message_poll`
- `frida_rpc_call`
- `frida_script_post`
- `frida_test_strings`

Not: `frida_hook_start` icin `stream: true` verilirse SSE uzerinden `frida/event` bildirimi gonderilir.

### Spawn ile erken hook akisi

Hedefi bastan izlemek icin tipik akis:
1) `frida_spawn` ile proses suspended baslatilir
2) `frida_script_load` ile hook scripti yuklenir
3) `frida_resume` ile devam ettirilir

## Frida Araclari (Detay)

### frida_list_processes
- Amac: Calisan prosesleri listeler.
- Gerekli: yok.
- Cikti: `[{Pid, Name}]`.

### frida_spawn
- Amac: Proses suspended baslatir (erken hook icin).
- Gerekli: `program` (veya `path`).
- Opsiyonel: `args` (string[]).
- Cikti: `{ pid, argv }`.
- Ornek:
```json
{"program":"C:\\\\Program Files\\\\App\\\\app.exe","args":["-v"]}
```

### frida_resume
- Amac: Spawn edilen prosesi devam ettirir.
- Gerekli: `pid`.
- Cikti: `{ pid, resumed: true }`.

### frida_kill
- Amac: Proses sonlandirir.
- Gerekli: `pid`.
- Cikti: `{ pid, killed: true }`.

### frida_attach
- Amac: Proses attach eder.
- Gerekli: `pid`.
- Cikti: `{ sessionId, pid, attach: {...} }`.

### frida_list_modules
- Amac: Modul listesini doner.
- Gerekli: `pid` veya `sessionId`.
- Cikti: `{ data: [{name, base, size, path}] }`.

### frida_list_exports
- Amac: Modul export listesi.
- Gerekli: `pid` veya `sessionId`, `module`.
- Cikti: `{ data: [{name, address, type}] }`.

### frida_read_memory
- Amac: Bellekten hex okur.
- Gerekli: `pid` veya `sessionId`, `address`, `size`.
- Cikti: `{ data, size }`.

### frida_read_string
- Amac: Bellekten string okur.
- Gerekli: `pid` veya `sessionId`, `address`.
- Opsiyonel: `maxLength`, `encoding` (utf8/utf16/ascii).
- Cikti: `{ data }` (gerekirse fallback bilgisi ile).

### frida_scan_memory
- Amac: Bellek tarama.
- Gerekli: `pid` veya `sessionId`, `address`, `size`, `pattern`.
- Cikti: `{ data: [address...] }`.

### frida_write_memory
- Amac: Bellege hex yazar.
- Gerekli: `pid` veya `sessionId`, `address`, `dataHex`.
- Cikti: `{ data: { written } }`.

### frida_call_function
- Amac: Adresteki fonksiyonu cagirir.
- Gerekli: `pid` veya `sessionId`, `address`, `argTypes`, `argValues`.
- Opsiyonel: `returnType` (default `pointer`).
- Cikti: `{ data: { result } }`.

### frida_hook_start
- Amac: Kalici hook baslatir.
- Gerekli: `pid` veya `sessionId`, `address` veya (`module` + `export`).
- Opsiyonel: `includeArgs`, `includeRetval`, `includeBacktrace`, `maxArgs`, `once`, `autoStop`, `stream`, `pollIntervalMs`, `maxEvents`.
- Cikti: `{ hookId }`.

### frida_hook_poll
- Amac: Hook event listesi.
- Gerekli: `hookId`.
- Opsiyonel: `maxEvents`.
- Cikti: `{ events: [...] }`.

### frida_hook_stop
- Amac: Hook durdurur.
- Gerekli: `hookId`.
- Cikti: `{ stopped }`.

### frida_set_breakpoint
- Amac: Breakpoint (hook tabanli) kurar.
- Gerekli: `pid` veya `sessionId`, `address` veya (`module` + `export`).
- Opsiyonel: `includeArgs`, `includeRetval`, `includeBacktrace`, `maxArgs`, `once`, `autoStop`, `stream`, `pollIntervalMs`, `maxEvents`.
- Cikti: `{ hookId }`.

### frida_script_load
- Amac: JS script inject eder.
- Gerekli: `pid` veya `sessionId`, `source`.
- Cikti: `{ scriptId }`.

### frida_script_unload
- Amac: Script kaldirir.
- Gerekli: `scriptId`.
- Cikti: `{ scriptId, stopped }`.

### frida_script_message_poll
- Amac: Script `send()` mesajlarini okur.
- Gerekli: `scriptId`.
- Opsiyonel: `maxEvents`.
- Cikti: `{ events: [...] }`.

### frida_rpc_call
- Amac: `rpc.exports` method cagirir.
- Gerekli: `scriptId`, `method`.
- Opsiyonel: `args`, `timeoutMs`.
- Cikti: `{ result }`.

### frida_script_post
- Amac: Script tarafindaki `recv()` icin payload gonderir.
- Gerekli: `scriptId`, `payload`.
- Cikti: `{ ok }`.

### frida_test_strings
- Amac: Hedef proses icinde test stringleri allocate eder.
- Gerekli: `pid` veya `sessionId`.
- Opsiyonel: `asciiText`, `utf16Text`, `timeoutMs`.
- Cikti: `{ scriptId, asciiPtr, utf16Ptr }`.

## GUI Notlari

- WPF GUI sadece Windows icin. `dotnet` PATH icinde olmali.
- GUI, gateway ve worker baslatmak icin `dotnet run` kullanir (path ve argumanlari UI'dan girebilirsiniz).
- Ngrok sekmesi icin `ngrok.exe` varsayilan olarak `mcp-platform/ngrok/ngrok.exe` bekler.

## Script Enjeksiyon Notlari

- `frida.script_load` icin `source` zorunludur ve JS kodu tek string olarak gonderilmelidir.
- `frida.rpc_call` icin `rpc.exports` altinda method gerekir.
- `frida.script_message_poll` `send()` ile gelen mesajlari dondurur.
- `frida.script_post` `recv()` icin host tarafindan mesaj gonderir.

## Test Fixture

- `frida.test_strings` hedef proses icinde UTF-8 ve UTF-16 string allocate eder, `scriptId` ve adresleri dondurur.
- Adreslerden `frida.read_string` ile dogrulama yapabilirsiniz.

## SSE MCP Uclari

- `GET /sse` (SSE baglantisi)
- `POST /message?sessionId=...`

Token gerekiyorsa:
- Header: `Authorization: Bearer <token>`
- veya query: `?token=<token>`

## Ngrok

```
ngrok http 13338
```

Ngrok URL'sini MCP istemcisine SSE olarak verin.
