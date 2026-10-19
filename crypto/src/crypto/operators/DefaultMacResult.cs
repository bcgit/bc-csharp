using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The result of a MAC calculation.</summary>
    public sealed class DefaultMacResult
        : IBlockResult
    {
        private readonly IMac m_mac;

        /// <summary>Create a new <see cref="DefaultMacResult"/>.</summary>
        /// <param name="mac">The MAC.</param>
        public DefaultMacResult(IMac mac)
        {
            m_mac = mac;
        }

        /// <inheritdoc/>
        public byte[] Collect() => MacUtilities.DoFinal(m_mac);

        /// <inheritdoc/>
        public int Collect(byte[] buf, int off) => m_mac.DoFinal(buf, off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int Collect(Span<byte> output) => m_mac.DoFinal(output);
#endif

        /// <inheritdoc/>
        public int GetMaxResultLength() => m_mac.GetMacSize();
    }
}
