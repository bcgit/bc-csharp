using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: CLSCompliant(true)]
[assembly: ComVisible(false)]

// The test assembly is signed with the same key (BouncyCastle.NET.snk), so it can see internal types and members.
[assembly: InternalsVisibleTo("BouncyCastle.Crypto.Tests, PublicKey="
    + "002400000480000094000000060200000024000052534131000400000100010011ad02b18bd73070ff2cf70191f57fa3952b5f847d"
    + "5ca57063756779e1c86699cbdcff785f8144cb30d045f676231b731ae3202de52c3eb09df201595871652d8e4550e35c16535d63d6"
    + "7ffa5d7b8f2a9d8cf77b0c3b5857f45c796579a87246492ab0d391fb620db5f8e2ba2d5f261e35ac056081846139236083326d3fbdd1")]
