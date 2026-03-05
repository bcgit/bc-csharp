```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.7918/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i9-13900K 3.00GHz, 1 CPU, 32 logical and 24 physical cores
.NET SDK 10.0.200-preview.0.26103.119
  [Host]               : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET 10.0            : .NET 10.0.3 (10.0.3, 10.0.326.7603), X64 RyuJIT x86-64-v3
  .NET Framework 4.8.1 : .NET Framework 4.8.1 (4.8.9325.0), X64 RyuJIT VectorSize=256


```
| Method            | Job                  | Runtime              | ArraySize | Mean      | Ratio | Gen0   | Gen1   | Allocated | Alloc Ratio |
|------------------ |--------------------- |--------------------- |---------- |----------:|------:|-------:|-------:|----------:|------------:|
| **ArrayClone**        | **.NET 10.0**            | **.NET 10.0**            | **16**        | **33.286 ns** |  **1.00** | **0.0021** |      **-** |      **40 B** |        **1.00** |
| NewArrayBlockCopy | .NET 10.0            | .NET 10.0            | 16        |  4.787 ns |  0.14 | 0.0021 |      - |      40 B |        1.00 |
|                   |                      |                      |           |           |       |        |        |           |             |
| ArrayClone        | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 16        | 18.655 ns |  1.00 | 0.0063 |      - |      40 B |        1.00 |
| NewArrayBlockCopy | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 16        |  7.217 ns |  0.39 | 0.0064 |      - |      40 B |        1.00 |
|                   |                      |                      |           |           |       |        |        |           |             |
| **ArrayClone**        | **.NET 10.0**            | **.NET 10.0**            | **128**       | **33.653 ns** |  **1.00** | **0.0080** |      **-** |     **152 B** |        **1.00** |
| NewArrayBlockCopy | .NET 10.0            | .NET 10.0            | 128       |  7.731 ns |  0.23 | 0.0081 |      - |     152 B |        1.00 |
|                   |                      |                      |           |           |       |        |        |           |             |
| ArrayClone        | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 128       | 22.591 ns |  1.00 | 0.0242 |      - |     152 B |        1.00 |
| NewArrayBlockCopy | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 128       | 11.276 ns |  0.50 | 0.0242 |      - |     152 B |        1.00 |
|                   |                      |                      |           |           |       |        |        |           |             |
| **ArrayClone**        | **.NET 10.0**            | **.NET 10.0**            | **1024**      | **50.312 ns** |  **1.00** | **0.0555** | **0.0002** |    **1048 B** |        **1.00** |
| NewArrayBlockCopy | .NET 10.0            | .NET 10.0            | 1024      | 33.917 ns |  0.67 | 0.0557 | 0.0002 |    1048 B |        1.00 |
|                   |                      |                      |           |           |       |        |        |           |             |
| ArrayClone        | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 1024      | 44.428 ns |  1.00 | 0.1670 | 0.0007 |    1051 B |        1.00 |
| NewArrayBlockCopy | .NET Framework 4.8.1 | .NET Framework 4.8.1 | 1024      | 34.993 ns |  0.79 | 0.1670 | 0.0007 |    1051 B |        1.00 |
