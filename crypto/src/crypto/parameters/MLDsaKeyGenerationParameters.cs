using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLDsaParameters m_parameters;

        public MLDsaKeyGenerationParameters(SecureRandom random, MLDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public MLDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!MLDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised ML-DSA parameters OID", nameof(parametersOid));
        }

        public MLDsaParameters Parameters => m_parameters;
    }
}
