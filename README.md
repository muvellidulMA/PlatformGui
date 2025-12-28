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

## Frida Araclari

- `frida.list_processes`
- `frida.attach`
- `frida.list_modules`
- `frida.list_exports`
- `frida.read_memory`
- `frida.read_string`
- `frida.scan_memory`
- `frida.write_memory`
- `frida.call_function`
- `frida.hook_start`
- `frida.hook_poll`
- `frida.hook_stop`
- `frida.set_breakpoint`

Not: `frida.hook_start` icin `stream: true` verilirse SSE uzerinden `frida/event` bildirimi gonderilir.

## GUI Notlari

- WPF GUI sadece Windows icin. `dotnet` PATH icinde olmali.
- GUI, gateway ve worker baslatmak icin `dotnet run` kullanir (path ve argumanlari UI'dan girebilirsiniz).
- Ngrok sekmesi icin `ngrok.exe` varsayilan olarak `mcp-platform/ngrok/ngrok.exe` bekler.

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
