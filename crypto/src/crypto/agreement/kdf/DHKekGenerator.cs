using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /**
    * RFC 2631 Diffie-hellman KEK derivation function.
    */
    public sealed class DHKekGenerator
        : IDerivationFunction
    {
        private readonly IDigest m_digest;

        private DerObjectIdentifier	algorithm;
        private int					keySize;
        private byte[]				z;
        private byte[]				partyAInfo;

        public DHKekGenerator(IDigest digest)
        {
            m_digest = digest;
        }

        public void Init(IDerivationParameters param)
        {
            DHKdfParameters parameters = (DHKdfParameters)param;

            this.algorithm = parameters.Algorithm;
            this.keySize = parameters.KeySize;
            this.z = parameters.GetZ(); // TODO Clone?
            this.partyAInfo = parameters.GetExtraInfo(); // TODO Clone?
        }

        public IDigest Digest => m_digest;

        public int GenerateBytes(byte[]	outBytes, int outOff, int length)
        {
            Check.OutputLength(outBytes, outOff, length, "output buffer too small");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(outBytes.AsSpan(outOff, length));
#else
            long oBytes = length;
            int digestSize = m_digest.GetDigestSize();

            //
            // this is at odds with the standard implementation, the
            // maximum value should be hBits * (2^32 - 1) where hBits
            // is the digest output size in bits. We can't have an
            // array with a long index at the moment...
            //
            if (oBytes > ((2L << 32) - 1))
                throw new ArgumentException("Output length too large");

            int cThreshold = (int)((oBytes + digestSize - 1) / digestSize);

            byte[] dig = new byte[digestSize];

            uint counter = 1;

            for (int i = 0; i < cThreshold; i++)
            {
                // KeySpecificInfo
                DerSequence keyInfo = new DerSequence(algorithm, new DerOctetString(Pack.UInt32_To_BE(counter)));

                // OtherInfo
                Asn1EncodableVector v1 = new Asn1EncodableVector(keyInfo);

                if (partyAInfo != null)
                {
                    v1.Add(new DerTaggedObject(true, 0, new DerOctetString(partyAInfo)));
                }

                v1.Add(new DerTaggedObject(true, 2, new DerOctetString(Pack.UInt32_To_BE((uint)keySize))));

                byte[] other = new DerSequence(v1).GetDerEncoded();

                m_digest.BlockUpdate(z, 0, z.Length);
                m_digest.BlockUpdate(other, 0, other.Length);
                m_digest.DoFinal(dig, 0);

                if (length > digestSize)
                {
                    Array.Copy(dig, 0, outBytes, outOff, digestSize);
                    outOff += digestSize;
                    length -= digestSize;
                }
                else
                {
                    Array.Copy(dig, 0, outBytes, outOff, length);
                }

                counter++;
            }

            m_digest.Reset();

            return (int)oBytes;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output)
        {
            long oBytes = output.Length;
            int digestSize = m_digest.GetDigestSize();

            //
            // this is at odds with the standard implementation, the
            // maximum value should be hBits * (2^32 - 1) where hBits
            // is the digest output size in bits. We can't have an
            // array with a long index at the moment...
            //
            if (oBytes > ((2L << 32) - 1))
                throw new ArgumentException("Output length too large");

            int cThreshold = (int)((oBytes + digestSize - 1) / digestSize);

            Span<byte> dig = stackalloc byte[digestSize];

            uint counter = 1;

            for (int i = 0; i < cThreshold; i++)
            {
                // KeySpecificInfo
                DerSequence keyInfo = new DerSequence(algorithm, new DerOctetString(Pack.UInt32_To_BE(counter)));

                // OtherInfo
                Asn1EncodableVector v1 = new Asn1EncodableVector(keyInfo);

                if (partyAInfo != null)
                {
                    v1.Add(new DerTaggedObject(true, 0, new DerOctetString(partyAInfo)));
                }

                v1.Add(new DerTaggedObject(true, 2, new DerOctetString(Pack.UInt32_To_BE((uint)keySize))));

                byte[] other = new DerSequence(v1).GetDerEncoded();

                m_digest.BlockUpdate(z);
                m_digest.BlockUpdate(other);
                m_digest.DoFinal(dig);

                int remaining = output.Length;
                if (remaining > digestSize)
                {
                    dig.CopyTo(output);
                    output = output[digestSize..];
                }
                else
                {
                    dig[..remaining].CopyTo(output);
                }

                counter++;
            }

            m_digest.Reset();

            return (int)oBytes;
        }
#endif
    }
}
