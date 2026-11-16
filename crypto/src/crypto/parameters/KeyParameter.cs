using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for symmetric key parameters.</summary>
    public class KeyParameter
        : ICipherParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a key parameter by filling a new key of the given length via a callback.</summary>
        /// <param name="length">The length of the key in bytes.</param>
        /// <param name="state">The state to pass to the callback.</param>
        /// <param name="action">The callback that fills the key.</param>
        /// <returns>The key parameter.</returns>
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

        /// <summary>Initializes a new instance of <see cref="KeyParameter"/>.</summary>
        /// <param name="key">The byte array containing the key material.</param>
        public KeyParameter(byte[] key)
        {
            m_key = Arrays.CopyBuffer(key);
        }

        /// <summary>Initializes a new instance of <see cref="KeyParameter"/>.</summary>
        /// <param name="key">The byte array containing the key material.</param>
        /// <param name="keyOff">The offset into the byte array where the key starts.</param>
        /// <param name="keyLen">The length of the key material.</param>
        public KeyParameter(byte[] key, int keyOff, int keyLen)
        {
            m_key = Arrays.CopySegment(key, keyOff, keyLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a new <see cref="KeyParameter"/>.</summary>
        /// <param name="key">The key.</param>
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

        /// <summary>Copy the key to a buffer.</summary>
        /// <param name="buf">The buffer to copy to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        /// <param name="len">The number of bytes expected, which must equal the key length.</param>
        public void CopyKeyTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_key, buf, off, len);

        /// <summary>Copy the key to a buffer.</summary>
        /// <param name="buf">The buffer to copy to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        /// <param name="len">The number of bytes expected, which must equal the key length.</param>
        [Obsolete("Use 'CopyKeyTo' instead")]
        public void CopyTo(byte[] buf, int off, int len)
        {
            if (m_key.Length != len)
                throw new ArgumentOutOfRangeException(nameof(len));

            Array.Copy(m_key, 0, buf, off, len);
        }

        /// <summary>Gets the key material.</summary>
        /// <returns>A copy of the key material as a byte array.</returns>
        public byte[] GetKey() => Arrays.InternalCopyBuffer(m_key);

        /// <summary>Gets the length of the key material in bytes.</summary>
        public int KeyLength => m_key.Length;

        internal bool FixedTimeEquals(byte[] data) => Arrays.FixedTimeEquals(m_key, data);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalKey => m_key;
#endif

        /// <summary>Create a key parameter holding the bytes of this key in reverse order.</summary>
        /// <returns>The new key parameter.</returns>
        public KeyParameter Reverse()
        {
            var reversed = new KeyParameter(m_key.Length);
            Arrays.Reverse(m_key, reversed.m_key);
            return reversed;
        }
    }
}
