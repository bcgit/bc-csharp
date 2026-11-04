using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for Digital Signature Algorithm (DSA) key parameters.</summary>
    public abstract class DsaKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly DsaParameters parameters;

        /// <summary>Initializes a new instance of <see cref="DsaKeyParameters"/>.</summary>
        /// <param name="isPrivate">Whether the key is private or not.</param>
        /// <param name="parameters">The DSA domain parameters.</param>
        protected DsaKeyParameters(
            bool isPrivate,
            DsaParameters parameters)
            : base(isPrivate)
        {
            // Note: parameters may be null
            this.parameters = parameters;
        }

        /// <summary>Gets the DSA domain parameters.</summary>
        public DsaParameters Parameters => parameters;

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            if (obj == this)
                return true;

            DsaKeyParameters other = obj as DsaKeyParameters;

            if (other == null)
                return false;

            return Equals(other);
        }

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected bool Equals(
            DsaKeyParameters other)
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
