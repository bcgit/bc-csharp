using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class LmsUtilities
    {
        public static void U32Str(int n, IDigest d)
        {
            d.Update((byte)(n >> 24));
            d.Update((byte)(n >> 16));
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void U16Str(short n, IDigest d)
        {
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void ByteArray(byte[] array, IDigest digest)
        {
            digest.BlockUpdate(array, 0, array.Length);
        }

        public static void ByteArray(byte[] array, int start, int len, IDigest digest)
        {
            digest.BlockUpdate(array, start, len);
        }

        public static int CalculateStrength(LmsParameters lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));

            LMSigParameters sigParameters = lmsParameters.LMSigParameters;
            return sigParameters.M << sigParameters.H;
        }

        internal static IDigest GetDigest(LMOtsParameters otsParameters) =>
            CreateDigest(otsParameters.DigestOid, otsParameters.N);

        internal static IDigest GetDigest(LMSigParameters sigParameters) =>
            CreateDigest(sigParameters.DigestOid, sigParameters.M);

        private static IDigest CreateDigest(DerObjectIdentifier oid, int length)
        {
            // TODO Perhaps support length-specified digests directly in DigestUtilities?

            IDigest digest = CreateDigest(oid);

            if (NistObjectIdentifiers.IdShake256Len.Equals(oid) ||
                digest.GetDigestSize() != length)
            {
                return new WrapperDigest(digest, length);
            }

            return digest;
        }

        private static IDigest CreateDigest(DerObjectIdentifier oid)
        {
            if (NistObjectIdentifiers.IdSha256.Equals(oid))
                return DigestUtilities.GetDigest(NistObjectIdentifiers.IdSha256);

            if (NistObjectIdentifiers.IdShake256Len.Equals(oid))
                return DigestUtilities.GetDigest(NistObjectIdentifiers.IdShake256);

            throw new LmsException("unrecognized digest OID: " + oid);
        }

        internal class WrapperDigest
            : IDigest
        {
            private readonly IDigest m_digest;
            private readonly int m_length;

            internal WrapperDigest(IDigest digest, int length)
            {
                m_digest = digest;
                m_length = length;
            }

            public string AlgorithmName => m_digest.AlgorithmName;

            public void BlockUpdate(byte[] input, int inOff, int inLen) => m_digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public void BlockUpdate(ReadOnlySpan<byte> input) => m_digest.BlockUpdate(input);
#endif

            public int DoFinal(byte[] output, int outOff)
            {
                byte[] buf = new byte[m_digest.GetDigestSize()];
                m_digest.DoFinal(buf, 0);

                Array.Copy(buf, 0, output, outOff, m_length);
                return m_length;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public int DoFinal(Span<byte> output) 
            {
                int digestSize = m_digest.GetDigestSize();
                Span<byte> buf = digestSize <= 128
                    ? stackalloc byte[digestSize]
                    : new byte[digestSize];

                m_digest.DoFinal(buf);

                buf[..m_length].CopyTo(output);
                return m_length;
            }
#endif

            public int GetByteLength() => m_digest.GetByteLength();

            public int GetDigestSize() => m_length;

            public void Reset() => m_digest.Reset();

            public void Update(byte input) => m_digest.Update(input);
        }
    }
}
