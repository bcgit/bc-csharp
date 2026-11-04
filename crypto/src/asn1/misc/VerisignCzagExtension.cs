using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>The Verisign CZAG extension.</summary>
    public class VerisignCzagExtension
        : DerIA5String
    {
        /// <summary>Create a new <see cref="VerisignCzagExtension"/>.</summary>
        /// <param name="str">The str.</param>
        public VerisignCzagExtension(DerIA5String str)
            : base(str.GetString())
        {
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return "VerisignCzagExtension: " + this.GetString();
        }
    }
}
