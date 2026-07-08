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
        public PolicyUrl(bool critical, string url)
            : this(critical, isLongLength: false, Strings.ToUtf8ByteArray(url))
        {
        }

        public PolicyUrl(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PolicyUrl, critical, isLongLength, data)
        {
        }

        public string Url => Strings.FromUtf8ByteArray(Data);

        public byte[] GetRawUrl() => GetData();
    }
}
