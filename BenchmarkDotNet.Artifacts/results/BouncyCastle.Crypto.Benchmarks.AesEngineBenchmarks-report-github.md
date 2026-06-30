```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.7918/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i9-13900K 3.00GHz, 1 CPU, 32 logical and 24 physical cores
.NET SDK 10.0.200-preview.0.26103.119
  [Host]               : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET 10.0            : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET Framework 4.8.1 : .NET Framework 4.8.1 (4.8.9325.0), X64 RyuJIT VectorSize=256

InvocationCount=1  UnrollFactor=1  

```
| Method       | Job                  | Runtime              | Mean       | Allocated |
|------------- |--------------------- |--------------------- |-----------:|----------:|
| Init         | .NET 10.0            | .NET 10.0            |   883.8 ns |     200 B |
| ProcessBlock | .NET 10.0            | .NET 10.0            |   422.0 ns |         - |
| Init         | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 1,480.6 ns |         - |
| ProcessBlock | .NET Framework 4.8.1 | .NET Framework 4.8.1 |   142.1 ns |         - |
