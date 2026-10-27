namespace Org.BouncyCastle.Asn1
{
    /// <summary>Base class for the ASN.1 character string types.</summary>
    public abstract class DerStringBase
        : Asn1Object, IAsn1String
    {
        /// <summary>Create a new <see cref="DerStringBase"/>.</summary>
        protected DerStringBase()
        {
        }

        /// <inheritdoc/>
        public abstract string GetString();

        /// <inheritdoc/>
        public override string ToString()
        {
            return GetString();
        }

        /// <inheritdoc/>
        protected override int Asn1GetHashCode()
        {
            return GetString().GetHashCode();
        }
    }
}
