using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public sealed class ECDHRawAgreement
        : IRawAgreement
    {
        private ECPrivateKeyParameters m_privKey;

        public void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is ECPrivateKeyParameters ecPrivateKeyParameters))
                throw new ArgumentException($"{nameof(ECDHRawAgreement)} expects {nameof(ECPrivateKeyParameters)}");

            m_privKey = ecPrivateKeyParameters;
        }

        public int AgreementSize => m_privKey.Parameters.Curve.FieldElementEncodingLength;

        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            ECDHBasicAgreement.CalculateAgreementFieldElement(m_privKey, (ECPublicKeyParameters)publicKey)
                .EncodeTo(buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> output)
        {
            ECDHBasicAgreement.CalculateAgreementFieldElement(m_privKey, (ECPublicKeyParameters)publicKey)
                .EncodeTo(output[..AgreementSize]);
        }
#endif
    }
}
