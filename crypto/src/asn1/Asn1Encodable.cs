using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Base class for objects that can be encoded as ASN.1.</summary>
    public abstract class Asn1Encodable
        : IAsn1Convertible
    {
        /// <summary>The <c>Ber</c> constant, with the value <c>BER</c>.</summary>
        public const string Ber = "BER";
        /// <summary>The <c>Der</c> constant, with the value <c>DER</c>.</summary>
        public const string Der = "DER";
        /// <summary>The <c>DL</c> constant, with the value <c>DL</c>.</summary>
        public const string DL = "DL";

        public virtual void EncodeTo(Stream output) => ToAsn1Object().EncodeTo(output);

        public virtual void EncodeTo(Stream output, string encoding) => ToAsn1Object().EncodeTo(output, encoding);

        /// <summary>Return the encoded.</summary>
        // TODO[api] Make virtual and override in Asn1Object
        public byte[] GetEncoded() => GetEncoded(Ber, preAlloc: 0, postAlloc: 0);

        // TODO[api] Make virtual and override in Asn1Object
        public byte[] GetEncoded(string encoding) => GetEncoded(encoding, preAlloc: 0, postAlloc: 0);

        internal virtual byte[] GetEncoded(string encoding, int preAlloc, int postAlloc) =>
            ToAsn1Object().GetEncoded(encoding, preAlloc, postAlloc);

        /// <summary>Return the DER encoding of the object, null if the DER encoding can not be made.</summary>
        /// <returns>a DER byte array, null otherwise.</returns>
        public byte[] GetDerEncoded()
        {
            try
            {
                return GetEncoded(Der);
            }
            catch (IOException)
            {
                return null;
            }
        }

        /// <inheritdoc/>
        public sealed override int GetHashCode() => ToAsn1Object().CallAsn1GetHashCode();

        /// <inheritdoc/>
        public sealed override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            if (!(obj is IAsn1Convertible that))
                return false;

            Asn1Object o1 = this.ToAsn1Object();
            Asn1Object o2 = that.ToAsn1Object();

            return o1 == o2 || (null != o2 && o1.CallAsn1Equals(o2));
        }

        /// <inheritdoc/>
        public abstract Asn1Object ToAsn1Object();
    }
}
