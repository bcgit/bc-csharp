using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>The Netscape revocation URL extension.</summary>
    public class NetscapeRevocationUrl
        : DerIA5String
    {
        /// <summary>Create a new <see cref="NetscapeRevocationUrl"/>.</summary>
        /// <param name="str">The str.</param>
        public NetscapeRevocationUrl(DerIA5String str)
            : base(str.GetString())
        {
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return "NetscapeRevocationUrl: " + this.GetString();
        }
    }
}
