using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <remarks>Parameters for mask derivation functions.</remarks>
    public sealed class MgfParameters
        : IDerivationParameters
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create MGF parameters by filling a new seed of the given length via a callback.</summary>
        /// <param name="length">The length of the seed in bytes.</param>
        /// <param name="state">The state to pass to the callback.</param>
        /// <param name="action">The callback that fills the seed.</param>
        /// <returns>The parameters.</returns>
        public static MgfParameters Create<TState>(int length, TState state, SpanAction<byte, TState> action)
        {
            if (action == null)
                throw new ArgumentNullException(nameof(action));
            if (length < 1)
                throw new ArgumentOutOfRangeException(nameof(length));

            MgfParameters result = new MgfParameters(length);
            action(result.m_seed, state);
            return result;
        }
#endif

        private readonly byte[] m_seed;

        /// <summary>Create a new <see cref="MgfParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        public MgfParameters(byte[] seed)
        {
            m_seed = Arrays.CopyBuffer(seed);
        }

        /// <summary>Create a new <see cref="MgfParameters"/>.</summary>
        /// <param name="seed">The seed.</param>
        /// <param name="off">The offset into the array.</param>
        /// <param name="len">The number of bytes.</param>
        public MgfParameters(byte[] seed, int off, int len)
        {
            m_seed = Arrays.CopySegment(seed, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private MgfParameters(int length)
        {
            if (length < 1)
                throw new ArgumentOutOfRangeException(nameof(length));

            m_seed = new byte[length];
        }
#endif

        /// <summary>Copy the seed to a buffer.</summary>
        /// <param name="buf">The buffer to copy to.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which to start writing.</param>
        /// <param name="len">The number of bytes expected, which must equal the seed length.</param>
        public void CopySeedTo(byte[] buf, int off, int len) => Arrays.CopyBufferToSegment(m_seed, buf, off, len);

        /// <summary>Return the seed.</summary>
        public byte[] GetSeed() => Arrays.InternalCopyBuffer(m_seed);

        /// <summary>Return the seed.</summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="offset">The offset into the array.</param>
        [Obsolete("Use 'CopySeedTo' instead")]
        public void GetSeed(byte[] buffer, int offset) => m_seed.CopyTo(buffer, offset);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Return the seed.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        public void GetSeed(Span<byte> output)
        {
            m_seed.CopyTo(output);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> InternalSeed => m_seed;
#endif

        /// <summary>Gets the seed length.</summary>
        public int SeedLength => m_seed.Length;
    }
}
