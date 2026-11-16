using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for GOST R 34.10-94 keys.</summary>
    public abstract class Gost3410KeyParameters
        : AsymmetricKeyParameter
    {
        private readonly Gost3410Parameters parameters;
        private readonly DerObjectIdentifier publicKeyParamSet;

        /// <summary>Create a new <see cref="Gost3410KeyParameters"/>.</summary>
        /// <param name="isPrivate">true if is private, false otherwise.</param>
        /// <param name="parameters">The parameters.</param>
        protected Gost3410KeyParameters(
            bool isPrivate,
            Gost3410Parameters parameters)
            : base(isPrivate)
        {
            this.parameters = parameters;
        }

        /// <summary>Create a new <see cref="Gost3410KeyParameters"/>.</summary>
        /// <param name="isPrivate">true if is private, false otherwise.</param>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        protected Gost3410KeyParameters(
            bool isPrivate,
            DerObjectIdentifier publicKeyParamSet)
            : base(isPrivate)
        {
            this.parameters = LookupParameters(publicKeyParamSet);
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

        // TODO Implement Equals/GetHashCode

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
