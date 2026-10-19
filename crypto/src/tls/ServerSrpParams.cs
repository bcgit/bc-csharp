using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public sealed class ServerSrpParams
    {
        private BigInteger m_N, m_g, m_B;
        private byte[] m_s;

        /// <summary>Create a new <see cref="ServerSrpParams"/>.</summary>
        /// <param name="N">The n.</param>
        /// <param name="g">The g.</param>
        /// <param name="s">The s.</param>
        /// <param name="B">The b.</param>
        public ServerSrpParams(BigInteger N, BigInteger g, byte[] s, BigInteger B)
        {
            this.m_N = N;
            this.m_g = g;
            this.m_s = Arrays.Clone(s);
            this.m_B = B;
        }

        /// <summary>Gets the b.</summary>
        public BigInteger B
        {
            get { return m_B; }
        }

        /// <summary>Gets the g.</summary>
        public BigInteger G
        {
            get { return m_g; }
        }

        /// <summary>Gets the n.</summary>
        public BigInteger N
        {
            get { return m_N; }
        }

        /// <summary>Gets the s.</summary>
        public byte[] S
        {
            get { return m_s; }
        }

        /// <summary>Encode this <see cref="ServerSrpParams"/> to a <see cref="Stream"/>.</summary>
        /// <param name="output">the <see cref="Stream"/> to encode to.</param>
        /// <exception cref="IOException"/>
        public void Encode(Stream output)
        {
            TlsSrpUtilities.WriteSrpParameter(m_N, output);
            TlsSrpUtilities.WriteSrpParameter(m_g, output);
            TlsUtilities.WriteOpaque8(m_s, output);
            TlsSrpUtilities.WriteSrpParameter(m_B, output);
        }

        /// <summary>Parse a <see cref="ServerSrpParams"/> from a <see cref="Stream"/>.</summary>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="ServerSrpParams"/> object.</returns>
        /// <exception cref="IOException"/>
        public static ServerSrpParams Parse(Stream input)
        {
            BigInteger N = TlsSrpUtilities.ReadSrpParameter(input);
            BigInteger g = TlsSrpUtilities.ReadSrpParameter(input);
            byte[] s = TlsUtilities.ReadOpaque8(input, 1);
            BigInteger B = TlsSrpUtilities.ReadSrpParameter(input);

            return new ServerSrpParams(N, g, s, B);
        }
    }
}
