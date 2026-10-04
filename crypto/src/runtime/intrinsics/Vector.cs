#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
#endif

namespace Org.BouncyCastle.Runtime.Intrinsics
{
    internal static class Vector
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsPacked
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get =>
                Unsafe.SizeOf<Vector64<byte>>() == 8 &&
                Unsafe.SizeOf<Vector128<byte>>() == 16 &&
                Unsafe.SizeOf<Vector256<byte>>() == 32;
        }

        internal static bool IsPackedLittleEndian
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => IsPacked && BitConverter.IsLittleEndian;
        }
#else
        internal static bool IsPacked => false;

        internal static bool IsPackedLittleEndian => false;
#endif
    }
}
