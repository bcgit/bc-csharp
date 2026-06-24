using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public sealed class ECDhcRawAgreement
        : IRawAgreement
    {
        private ECPrivateKeyParameters m_privateKey;

        public void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is ECPrivateKeyParameters ecPrivateKeyParameters))
                throw new ArgumentException($"{nameof(ECDhcRawAgreement)} expects {nameof(ECPrivateKeyParameters)}");

            m_privateKey = ecPrivateKeyParameters;
        }

        public int AgreementSize => m_privateKey.Parameters.Curve.FieldElementEncodingLength;

        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            ECDHCBasicAgreement.CalculateAgreementFieldElement(m_privateKey, (ECPublicKeyParameters)publicKey)
                .EncodeTo(buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> output)
        {
            ECDHCBasicAgreement.CalculateAgreementFieldElement(m_privateKey, (ECPublicKeyParameters)publicKey)
                .EncodeTo(output[..AgreementSize]);
        }
#endif
    }
}
