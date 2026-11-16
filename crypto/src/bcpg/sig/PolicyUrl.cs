using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket for encoding a URI pointing to a document containing the policy under which the signature
    /// was created.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.20">RFC4880 - Policy URI</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-policy-uri">RFC9580 - Policy URI</see>
    /// </remarks>
    public class PolicyUrl
        : SignatureSubpacket
    {
        /// <summary>Create a new <see cref="PolicyUrl"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="url">The url.</param>
        public PolicyUrl(bool critical, string url)
            : this(critical, isLongLength: false, Strings.ToUtf8ByteArray(url))
        {
        }

        /// <summary>Create a new <see cref="PolicyUrl"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public PolicyUrl(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PolicyUrl, critical, isLongLength, data)
        {
        }

        /// <summary>Gets the url.</summary>
        public string Url => Strings.FromUtf8ByteArray(Data);

        /// <summary>Return the raw url.</summary>
        public byte[] GetRawUrl() => GetData();
    }
}
