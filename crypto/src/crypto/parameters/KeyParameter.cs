using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class KeyParameter
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static KeyParameter Create<TState>(int length, TState state, SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (length < 1)
                throw new ArgumentOutOfRangeException(nameof(length));

            KeyParameter result = new KeyParameter(length);
            action(result.m_key, state);
            return result;
        }
#endif

        private readonly byte[] m_key;

        public KeyParameter(byte[] key)
        {
            m_key = Arrays.CopyBuffer(key);
        }

        public KeyParameter(byte[] key, int keyOff, int keyLen)
        {
            m_key = Arrays.CopySegment(key, keyOff, keyLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public KeyParameter(ReadOnlySpan<byte> key)
        {
            m_key = key.ToArray();
        }
#endif

        private KeyParameter(int length)
        {
            if (length < 1)
                throw new ArgumentOutOfRangeException(nameof(length));

            m_key = new byte[length];
        }

        public void CopyKeyTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_key, buf, off, len);

        [Obsolete("Use 'CopyKeyTo' instead")]
        public void CopyTo(byte[] buf, int off, int len)
        {
            if (m_key.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            Array.Copy(m_key, 0, buf, off, len);
        }

        public byte[] GetKey() => Arrays.InternalCopyBuffer(m_key);

        public int KeyLength => m_key.Length;

        internal bool FixedTimeEquals(byte[] data) => Arrays.FixedTimeEquals(m_key, data);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalKey => m_key;
#endif

        public KeyParameter Reverse()
        {
            var reversed = new KeyParameter(m_key.Length);
            Arrays.Reverse(m_key, reversed.m_key);
            return reversed;
        }
    }
}
