#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace Org.BouncyCastle.Crypto.Digests
{
    internal static class VectorExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<T> BroadcastVector64ToVector128<T>(ReadOnlySpan<byte> source) where T : struct
        {
            Debug.Assert(source.Length == Unsafe.SizeOf<Vector64<byte>>());

            var vector = MemoryMarshal.Read<Vector64<T>>(source);
            Vector128<T> result = vector.ToVector128Unsafe();
            return result.WithUpper(vector);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> BroadcastVector128ToVector256<T>(ReadOnlySpan<byte> source) where T : struct
        {
            Debug.Assert(source.Length == Unsafe.SizeOf<Vector128<byte>>());

            var vector = MemoryMarshal.Read<Vector128<T>>(source);
            Vector256<T> result = vector.ToVector256Unsafe();
            return result.WithUpper(vector);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<T> LoadVector128<T>(ReadOnlySpan<byte> source) where T : struct
        {
            Debug.Assert(source.Length == Unsafe.SizeOf<Vector128<byte>>());
            return MemoryMarshal.Read<Vector128<T>>(source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> LoadVector256<T>(ReadOnlySpan<byte> source) where T : struct
        {
            Debug.Assert(source.Length == Unsafe.SizeOf<Vector256<byte>>());
            return MemoryMarshal.Read<Vector256<T>>(source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Store<T>(this Vector128<T> vector, Span<byte> destination) where T : struct
        {
            Debug.Assert(destination.Length == Unsafe.SizeOf<Vector128<byte>>());
            MemoryMarshal.Write(destination, ref vector);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Store<T>(this Vector256<T> vector, Span<byte> destination) where T : struct
        {
            Debug.Assert(destination.Length == Unsafe.SizeOf<Vector256<byte>>());
            MemoryMarshal.Write(destination, ref vector);
        }
    }
}
#endif