using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SlhDsaParameters m_parameters;

        public SlhDsaKeyGenerationParameters(SecureRandom random, SlhDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public SlhDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!SlhDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised SLH-DSA parameters OID", nameof(parametersOid));
        }

        public SlhDsaParameters Parameters => m_parameters;
    }
}
