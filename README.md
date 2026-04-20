# Hauyne

A managed (lie) .NET DLL injector injecting managed (truth) .NET DLLs for managed (truth) .NET processes.

Targets running .NET 5+ processes via hostfxr, injects into the default AssemblyLoadContext.

## Building

Run `./build.sh`.

Knobs:
* `./build.sh --no-zig` / `--no-dotnet` to skip a side
* `./build.sh --zig-targets "x86_64-linux-gnu x86_64-windows-gnu"` to narrow targets
* `CONFIG=Debug OPTIMIZE=Debug ./build.sh` for debug builds

## Requirements
* Matching .NET version with target (Targets .NET 9 out of the box)
* Matching arch with target
* Zig 
* .NET SDK
