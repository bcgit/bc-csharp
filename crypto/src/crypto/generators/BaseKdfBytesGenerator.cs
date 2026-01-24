using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * Basic KDF generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
     * <br/>
     * This implementation is based on ISO 18033/P1363a.
     */
    public abstract class BaseKdfBytesGenerator
        : IDerivationFunction
    {
        private readonly int m_counterStart;
        private readonly IDigest m_digest;

        private byte[] m_shared;
        private byte[] m_iv;

        /**
         * Construct a KDF Parameters generator.
         *
         * @param counterStart value of counter.
         * @param digest the digest to be used as the source of derived keys.
         */
        protected BaseKdfBytesGenerator(int counterStart, IDigest digest)
        {
            m_counterStart = counterStart;
            m_digest = digest;
        }

        public void Init(IDerivationParameters parameters)
        {
            if (parameters is KdfParameters kdfParameters)
            {
                m_shared = kdfParameters.GetSharedSecret();
                m_iv = kdfParameters.GetIV();
            }
            else if (parameters is Iso18033KdfParameters iso18033KdfParameters)
            {
                m_shared = iso18033KdfParameters.GetSeed();
                m_iv = null;
            }
            else
            {
                throw new ArgumentException("KDF parameters required for KDF Generator");
            }
        }

        public IDigest Digest => m_digest;

        /**
         * fill len bytes of the output buffer with bytes generated from
         * the derivation function.
         *
         * @throws ArgumentException if the size of the request will cause an overflow.
         * @throws DataLengthException if the out buffer is too small.
         */
        public int GenerateBytes(byte[] output, int outOff, int length)
        {
            Check.OutputLength(output, outOff, length, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(output.AsSpan(outOff, length));
#else
            m_digest.Reset();

            int outputLength = length;
            int digestSize = m_digest.GetDigestSize();

            // NOTE: This limit isn't reachable for current array lengths
            if (outputLength > ((1L << 32) - 1) * digestSize)
                throw new ArgumentException("Output length too large");

            uint counter32 = (uint)m_counterStart;
            byte[] C = new byte[4];

            while (length > 0)
            {
                Pack.UInt32_To_BE(counter32, C, 0);

                m_digest.BlockUpdate(m_shared, 0, m_shared.Length);
                m_digest.BlockUpdate(C, 0, 4);

                if (m_iv != null)
                {
                    m_digest.BlockUpdate(m_iv, 0, m_iv.Length);
                }

                if (length < digestSize)
                {
                    byte[] tmp = new byte[digestSize];
                    m_digest.DoFinal(tmp, 0);
                    Array.Copy(tmp, 0, output, outOff, length);
                    break;
                }

                m_digest.DoFinal(output, outOff);
                outOff += digestSize;
                length -= digestSize;

                ++counter32;
            }

            return outputLength;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output)
        {
            m_digest.Reset();

            int outputLength = output.Length;
            int digestSize = m_digest.GetDigestSize();

            // NOTE: This limit isn't reachable for current array lengths
            if (outputLength > ((1L << 32) - 1) * digestSize)
                throw new ArgumentException("Output length too large");

            Span<byte> dig = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];

            uint counter32 = (uint)m_counterStart;
            Span<byte> C = stackalloc byte[4];

            while (!output.IsEmpty)
            {
                Pack.UInt32_To_BE(counter32, C);

                m_digest.BlockUpdate(m_shared);
                m_digest.BlockUpdate(C);

                if (m_iv != null)
                {
                    m_digest.BlockUpdate(m_iv);
                }

                if (output.Length < digestSize)
                {
                    Span<byte> tmp = digestSize <= 128
                        ? stackalloc byte[digestSize]
                        : new byte[digestSize];
                    m_digest.DoFinal(tmp);
                    output.CopyFrom(tmp);
                    break;
                }

                m_digest.DoFinal(output[..digestSize]);
                output = output[digestSize..];

                ++counter32;
            }

            return outputLength;
        }
#endif
    }
}
