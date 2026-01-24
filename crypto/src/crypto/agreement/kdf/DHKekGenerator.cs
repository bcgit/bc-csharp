using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Utilities;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /// <summary>RFC 2631 Diffie-hellman KEK derivation function.</summary>
    public sealed class DHKekGenerator
        : IDerivationFunction
    {
        private readonly IDigest m_digest;

        private DHKdfParameters m_parameters;

        public DHKekGenerator(IDigest digest)
        {
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
        }

        public void Init(IDerivationParameters param)
        {
            m_parameters = (DHKdfParameters)param ?? throw new ArgumentNullException(nameof(param));
        }

        public IDigest Digest => m_digest;

        public int GenerateBytes(byte[]	outBytes, int outOff, int length)
        {
            Check.OutputLength(outBytes, outOff, length, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(outBytes.AsSpan(outOff, length));
#else
            m_digest.Reset();

            int outputLength = length;
            int digestSize = m_digest.GetDigestSize();

            // NOTE: This limit isn't reachable for current array lengths
            if (outputLength > ((1L << 32) - 1) * digestSize)
                throw new ArgumentException("Output length too large");

            var z = m_parameters.Z;

            uint counter32 = 0;
            byte[] counterOctets = new byte[4];
            var counter = DerOctetString.WithContents(counterOctets);
            var keyInfo = new KeySpecificInfo(m_parameters.Algorithm, counter);
            var partyAInfo = DerOctetString.WithContentsOptional(m_parameters.ExtraInfo);
            var suppPubInfo = DerOctetString.WithContents(Pack.UInt32_To_BE((uint)m_parameters.KeySize));
            var otherInfo = new OtherInfo(keyInfo, partyAInfo, suppPubInfo);

            var digestSink = new DigestSink(m_digest);

            while (length > 0)
            {
                m_digest.BlockUpdate(z, 0, z.Length);

                // NOTE: Modify counterOctets in-situ since counter is private to this method
                Pack.UInt32_To_BE(++counter32, counterOctets);
                otherInfo.EncodeTo(digestSink, Asn1Encodable.Der);

                if (length < digestSize)
                {
                    byte[] tmp = new byte[digestSize];
                    m_digest.DoFinal(tmp, 0);
                    Array.Copy(tmp, 0, outBytes, outOff, length);
                    break;
                }

                m_digest.DoFinal(outBytes, outOff);
                outOff += digestSize;
                length -= digestSize;
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

            // NOTE: This limit isn't reachable for current span lengths
            if (outputLength > ((1L << 32) - 1) * digestSize)
                throw new ArgumentException("Output length too large");

            var z = m_parameters.Z;

            uint counter32 = 0;
            byte[] counterOctets = new byte[4];
            var counter = DerOctetString.WithContents(counterOctets);
            var keyInfo = new KeySpecificInfo(m_parameters.Algorithm, counter);
            var partyAInfo = DerOctetString.WithContentsOptional(m_parameters.ExtraInfo);
            var suppPubInfo = DerOctetString.WithContents(Pack.UInt32_To_BE((uint)m_parameters.KeySize));
            var otherInfo = new OtherInfo(keyInfo, partyAInfo, suppPubInfo);

            var digestSink = new DigestSink(m_digest);

            while (!output.IsEmpty)
            {
                m_digest.BlockUpdate(z);

                // NOTE: Modify counterOctets in-situ since counter is private to this method
                Pack.UInt32_To_BE(++counter32, counterOctets);
                otherInfo.EncodeTo(digestSink, Asn1Encodable.Der);

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
            }

            return outputLength;
        }
#endif
    }
}
