using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms.Ecc;
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

        private DHKdfParameters m_parameters;

        public ECDHKekGenerator(IDigest digest)
        {
            m_kdf = new Kdf2BytesGenerator(digest);
        }

        public void Init(IDerivationParameters param)
        {
            m_parameters = (DHKdfParameters)param ?? throw new ArgumentNullException(nameof(param));
        }

        public IDigest Digest => m_kdf.Digest;

        public int GenerateBytes(byte[] outBytes, int outOff, int length)
        {
            Check.OutputLength(outBytes, outOff, length, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(outBytes.AsSpan(outOff, length));
#else
            InitKdf();
            return m_kdf.GenerateBytes(outBytes, outOff, length);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output)
        {
            InitKdf();
            return m_kdf.GenerateBytes(output);
        }
#endif

        private void InitKdf()
        {
            var keyInfo = m_parameters.AlgID;
            var entityUInfo = DerOctetString.WithContentsOptional(m_parameters.ExtraInfo);
            var suppPubInfo = DerOctetString.WithContents(Pack.UInt32_To_BE((uint)m_parameters.KeySize));
            var eccCmsSharedInfo = new ECC_CMS_SharedInfo(keyInfo, entityUInfo, suppPubInfo);
            byte[] iv = eccCmsSharedInfo.GetEncoded(Asn1Encodable.Der);
            m_kdf.Init(new KdfParameters(m_parameters.Z, iv));
        }
    }
}
