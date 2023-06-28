using System;
#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Diagnostics.CodeAnalysis;
#endif

namespace Org.BouncyCastle.Crypto
{
    internal static class Check
    {
        internal static void DataLength(bool condition, string message)
        {
            if (condition)
                ThrowDataLengthException(message);
        }

        internal static void DataLength(byte[] buf, int off, int len, string message)
        {
            if (off > (buf.Length - len))
                ThrowDataLengthException(message);
        }

        internal static void OutputLength(bool condition, string message)
        {
            if (condition)
                ThrowOutputLengthException(message);
        }

        internal static void OutputLength(byte[] buf, int off, int len, string message)
        {
            if (off > (buf.Length - len))
                ThrowOutputLengthException(message);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void DataLength<T>(ReadOnlySpan<T> input, int len, string message)
        {
            if (input.Length < len)
                ThrowDataLengthException(message);
        }

        internal static void OutputLength<T>(Span<T> output, int len, string message)
        {
            if (output.Length < len)
                ThrowOutputLengthException(message);
        }
#endif

#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [DoesNotReturn]
#endif
        internal static void ThrowDataLengthException(string message) => throw new DataLengthException(message);

#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [DoesNotReturn]
#endif
        internal static void ThrowOutputLengthException(string message) => throw new OutputLengthException(message);
    }
}
