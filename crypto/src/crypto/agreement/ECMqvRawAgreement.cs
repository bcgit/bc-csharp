using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public sealed class ECMqvRawAgreement
        : IRawAgreement
    {
        private MqvPrivateParameters m_privateParameters;

        public void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is MqvPrivateParameters mqvPrivateParameters))
                throw new ArgumentException($"{nameof(ECMqvRawAgreement)} expects {nameof(MqvPrivateParameters)}");

            m_privateParameters = mqvPrivateParameters;
        }

        public int AgreementSize =>
            m_privateParameters.StaticPrivateKey.Parameters.Curve.FieldElementEncodingLength;

        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            ECMqvBasicAgreement.CalculateAgreementFieldElement(m_privateParameters, (MqvPublicParameters)publicKey)
                .EncodeTo(buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> output)
        {
            ECMqvBasicAgreement.CalculateAgreementFieldElement(m_privateParameters, (MqvPublicParameters)publicKey)
                .EncodeTo(output[..AgreementSize]);
        }
#endif
    }
}
