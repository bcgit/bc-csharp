using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating GOST R 34.10-94 key pairs.</summary>
    public class Gost3410KeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly Gost3410Parameters parameters;
        private readonly DerObjectIdentifier publicKeyParamSet;

        /// <summary>Create a new <see cref="Gost3410KeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public Gost3410KeyGenerationParameters(
            SecureRandom random,
            Gost3410Parameters parameters)
            : base(random, parameters.P.BitLength - 1)
        {
            this.parameters = parameters;
        }

        /// <summary>Create a new <see cref="Gost3410KeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        public Gost3410KeyGenerationParameters(
            SecureRandom random,
            DerObjectIdentifier publicKeyParamSet)
            : this(random, LookupParameters(publicKeyParamSet))
        {
            this.publicKeyParamSet = publicKeyParamSet;
        }

        /// <summary>Gets the parameters.</summary>
        public Gost3410Parameters Parameters
        {
            get { return parameters; }
        }

        /// <summary>Gets the public key param set.</summary>
        public DerObjectIdentifier PublicKeyParamSet
        {
            get { return publicKeyParamSet; }
        }

        private static Gost3410Parameters LookupParameters(
            DerObjectIdentifier publicKeyParamSet)
        {
            if (publicKeyParamSet == null)
                throw new ArgumentNullException("publicKeyParamSet");

            Gost3410ParamSetParameters p = Gost3410NamedParameters.GetByOid(publicKeyParamSet);

            if (p == null)
                throw new ArgumentException("OID is not a valid CryptoPro public key parameter set", "publicKeyParamSet");

            return new Gost3410Parameters(p.P, p.Q, p.A);
        }
    }
}
