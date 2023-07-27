using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultMacResult
        : IBlockResult
    {
        private readonly IMac m_mac;

        public DefaultMacResult(IMac mac)
        {
            m_mac = mac;
        }

        public byte[] Collect() => MacUtilities.DoFinal(m_mac);

        public int Collect(byte[] buf, int off) => m_mac.DoFinal(buf, off);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output) => m_mac.DoFinal(output);
#endif

        public int GetMaxResultLength() => m_mac.GetMacSize();
    }
}
