using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLKemParameters m_parameters;

        public MLKemKeyGenerationParameters(SecureRandom random, MLKemParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public MLKemKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!MLKemParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised ML-KEM parameters OID", nameof(parametersOid));
        }

        public MLKemParameters Parameters => m_parameters;
    }
}
