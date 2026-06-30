```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.7918/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i9-13900K 3.00GHz, 1 CPU, 32 logical and 24 physical cores
.NET SDK 10.0.200-preview.0.26103.119
  [Host]               : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET 10.0            : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET Framework 4.8.1 : .NET Framework 4.8.1 (4.8.9325.0), X64 RyuJIT VectorSize=256


```
| Method               | Job                  | Runtime              | Mean     | 
|--------------------- |--------------------- |--------------------- |---------:|
| CloneSmall16Bytes    | .NET 10.0            | .NET 10.0            | 33.67 ns | 
| CloneMedium128Bytes  | .NET 10.0            | .NET 10.0            | 34.57 ns | 
| CloneLarge1024Bytes  | .NET 10.0            | .NET 10.0            | 54.17 ns | 
| CloneInt128Elements  | .NET 10.0            | .NET 10.0            | 43.81 ns | 
| CloneLong128Elements | .NET 10.0            | .NET 10.0            | 52.19 ns | 
| CloneSmall16Bytes    | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 19.86 ns | 
| CloneMedium128Bytes  | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 23.58 ns | 
| CloneLarge1024Bytes  | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 46.47 ns | 
| CloneInt128Elements  | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 32.95 ns | 
| CloneLong128Elements | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 45.18 ns | 
