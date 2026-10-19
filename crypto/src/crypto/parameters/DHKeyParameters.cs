using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for Diffie-Hellman keys.</summary>
    public class DHKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly DHParameters parameters;
        private readonly DerObjectIdentifier algorithmOid;

        /// <summary>Create a new <see cref="DHKeyParameters"/>.</summary>
        /// <param name="isPrivate">true if is private, false otherwise.</param>
        /// <param name="parameters">The parameters.</param>
        protected DHKeyParameters(
            bool isPrivate,
            DHParameters parameters)
            : this(isPrivate, parameters, PkcsObjectIdentifiers.DhKeyAgreement)
        {
        }

        /// <summary>Create a new <see cref="DHKeyParameters"/>.</summary>
        /// <param name="isPrivate">true if is private, false otherwise.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="algorithmOid">The algorithm object identifier.</param>
        protected DHKeyParameters(
            bool isPrivate,
            DHParameters parameters,
            DerObjectIdentifier algorithmOid)
            : base(isPrivate)
        {
            // TODO Should we allow parameters to be null?
            this.parameters = parameters;
            this.algorithmOid = algorithmOid;
        }

        /// <summary>Gets the parameters.</summary>
        public DHParameters Parameters
        {
            get { return parameters; }
        }

        /// <summary>Gets the algorithm oid.</summary>
        public DerObjectIdentifier AlgorithmOid
        {
            get { return algorithmOid; }
        }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            DHKeyParameters other = obj as DHKeyParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        protected bool Equals(
            DHKeyParameters other)
        {
            return Objects.Equals(parameters, other.parameters)
                && base.Equals(other);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            int hc = base.GetHashCode();

            if (parameters != null)
            {
                hc ^= parameters.GetHashCode();
            }

            return hc;
        }
    }
}
