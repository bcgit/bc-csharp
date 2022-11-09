using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /**
    * X9.63 based key derivation function for ECDH CMS.
    */
    public sealed class ECDHKekGenerator
        : IDerivationFunction
    {
        private readonly IDerivationFunction m_kdf;

        private DerObjectIdentifier	algorithm;
        private int					keySize;
        private byte[]				z;

        public ECDHKekGenerator(IDigest digest)
        {
            m_kdf = new Kdf2BytesGenerator(digest);
        }

        public void Init(IDerivationParameters param)
        {
            DHKdfParameters parameters = (DHKdfParameters)param;

            this.algorithm = parameters.Algorithm;
            this.keySize = parameters.KeySize;
            this.z = parameters.GetZ(); // TODO Clone?
        }

        public IDigest Digest => m_kdf.Digest;

        public int GenerateBytes(byte[]	outBytes, int outOff, int length)
        {
            Check.OutputLength(outBytes, outOff, length, "output buffer too small");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(outBytes.AsSpan(outOff, length));
#else
            // TODO Create an ASN.1 class for this (RFC3278)
            // ECC-CMS-SharedInfo
            DerSequence s = new DerSequence(
                new AlgorithmIdentifier(algorithm, DerNull.Instance),
                new DerTaggedObject(true, 2, new DerOctetString(Pack.UInt32_To_BE((uint)keySize))));

            m_kdf.Init(new KdfParameters(z, s.GetDerEncoded()));

            return m_kdf.GenerateBytes(outBytes, outOff, length);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output)
        {
            // TODO Create an ASN.1 class for this (RFC3278)
            // ECC-CMS-SharedInfo
            DerSequence s = new DerSequence(
                new AlgorithmIdentifier(algorithm, DerNull.Instance),
                new DerTaggedObject(true, 2, new DerOctetString(Pack.UInt32_To_BE((uint)keySize))));

            m_kdf.Init(new KdfParameters(z, s.GetDerEncoded()));

            return m_kdf.GenerateBytes(output);
        }
#endif
    }
}
