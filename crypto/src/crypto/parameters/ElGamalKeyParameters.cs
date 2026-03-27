using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Base class for ElGamal key parameters.</summary>
    public class ElGamalKeyParameters
		: AsymmetricKeyParameter
    {
        private readonly ElGamalParameters parameters;

        /// <summary>Initializes a new instance of <see cref="ElGamalKeyParameters"/>.</summary>
        /// <param name="isPrivate">Whether the key is private or not.</param>
        /// <param name="parameters">The ElGamal domain parameters.</param>
		protected ElGamalKeyParameters(
            bool				isPrivate,
            ElGamalParameters	parameters)
			: base(isPrivate)
        {
			// TODO Should we allow 'parameters' to be null?
            this.parameters = parameters;
        }

        /// <summary>Gets the ElGamal domain parameters.</summary>
		public ElGamalParameters Parameters => parameters;

		public override bool Equals(
            object obj)
        {
			if (obj == this)
				return true;

			ElGamalKeyParameters other = obj as ElGamalKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
        }

		protected bool Equals(
			ElGamalKeyParameters other)
		{
			return Objects.Equals(parameters, other.parameters)
				&& base.Equals(other);
		}

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
