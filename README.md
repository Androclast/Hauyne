# Hauyne

A managed (lie) .NET DLL injector injecting managed (truth) .NET DLLs for managed (truth) .NET processes.

Targets running .NET 5+ processes via hostfxr, injects into the default AssemblyLoadContext.

## Building

Run `./build.sh`.

Knobs:
* `./build.sh --no-zig` / `--no-dotnet` to skip a side
* `./build.sh --zig-targets "x86_64-linux-gnu x86_64-windows-gnu"` to narrow targets
* `CONFIG=Debug OPTIMIZE=Debug ./build.sh` for debug builds

## Usage

```
./Hauyne.Injector <process-name> [payload-path]
```

`<process-name>` is the process base name (no `.exe`). `[payload-path]` is optional; if omitted, the Bootstrap falls back to `Hauyne.Payload.dll` next to its own `.so`/`.dll`.

## Requirements

* Target must be a running .NET 5+ process
* Matching .NET version with target (targets .NET 9 out of the box)
* Matching arch with target
* Zig
* .NET SDK

### Linux

* x86-64 only
* Root, or `ptrace_scope` shuttered: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`

<img width="964" height="540" alt="image" src="https://github.com/user-attachments/assets/aa372ab7-4080-441a-a37f-b5a8a0d951ce" />

