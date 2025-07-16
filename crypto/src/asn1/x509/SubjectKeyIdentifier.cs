using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The SubjectKeyIdentifier object.
     * <pre>
     * SubjectKeyIdentifier::= OCTET STRING
     * </pre>
     */
    public class SubjectKeyIdentifier
        : Asn1Encodable
    {
        public static SubjectKeyIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SubjectKeyIdentifier subjectKeyIdentifier)
                return subjectKeyIdentifier;
            // TODO[api] Remove this case
            if (obj is SubjectPublicKeyInfo subjectPublicKeyInfo)
#pragma warning disable CS0618 // Type or member is obsolete
                return new SubjectKeyIdentifier(subjectPublicKeyInfo);
#pragma warning restore CS0618 // Type or member is obsolete
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            return new SubjectKeyIdentifier(Asn1OctetString.GetInstance(obj));
        }

        public static SubjectKeyIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new SubjectKeyIdentifier(Asn1OctetString.GetInstance(obj, explicitly));

        public static SubjectKeyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SubjectKeyIdentifier(Asn1OctetString.GetTagged(taggedObject, declaredExplicit));

        public static SubjectKeyIdentifier FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.SubjectKeyIdentifier));

        // TODO[api] Change to Asn1OctetString (careful because currently we always encode with DerOctetString)
        private readonly byte[] m_keyIdentifier;

        // TODO[api] Rename parameter
        public SubjectKeyIdentifier(byte[] keyID)
        {
            m_keyIdentifier = Arrays.Clone(keyID ?? throw new ArgumentNullException(nameof(keyID)));
        }

        // TODO[api] Rename parameter
        public SubjectKeyIdentifier(Asn1OctetString keyID)
            : this(keyID.GetOctets())
        {
        }

        /**
         * Calculates the keyIdentifier using a SHA1 hash over the BIT STRING
         * from SubjectPublicKeyInfo as defined in RFC3280.
         *
         * @param spki the subject public key info.
         */
        [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
        public SubjectKeyIdentifier(SubjectPublicKeyInfo spki)
        {
            m_keyIdentifier = GetDigest(spki);
        }

        public byte[] GetKeyIdentifier() => Arrays.Clone(m_keyIdentifier);

        // TODO[api] Add once m_keyIdentifier is an Asn1OctetString
        //public Asn1OctetString KeyIdentifier => m_keyIdentifier;

        public override Asn1Object ToAsn1Object() => DerOctetString.FromContents(m_keyIdentifier);

        /**
         * Return a RFC 3280 type 1 key identifier. As in:
         * <pre>
         * (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
         * value of the BIT STRING subjectPublicKey (excluding the tag,
         * length, and number of unused bits).
         * </pre>
         * @param keyInfo the key info object containing the subjectPublicKey field.
         * @return the key identifier.
         */
        [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
        public static SubjectKeyIdentifier CreateSha1KeyIdentifier(SubjectPublicKeyInfo keyInfo) =>
            new SubjectKeyIdentifier(keyInfo);

        /**
         * Return a RFC 3280 type 2 key identifier. As in:
         * <pre>
         * (2) The keyIdentifier is composed of a four bit type field with
         * the value 0100 followed by the least significant 60 bits of the
         * SHA-1 hash of the value of the BIT STRING subjectPublicKey.
         * </pre>
         * @param keyInfo the key info object containing the subjectPublicKey field.
         * @return the key identifier.
         */
        [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
        public static SubjectKeyIdentifier CreateTruncatedSha1KeyIdentifier(SubjectPublicKeyInfo keyInfo)
        {
            byte[] dig = GetDigest(keyInfo);
            byte[] id = new byte[8];

            Array.Copy(dig, dig.Length - 8, id, 0, id.Length);

            id[0] &= 0x0f;
            id[0] |= 0x40;

            return new SubjectKeyIdentifier(id);
        }

        private static byte[] GetDigest(SubjectPublicKeyInfo spki)
        {
            // TODO[api] This ASN.1 class is the wrong place for this calculation
            return DigestUtilities.CalculateDigest(OiwObjectIdentifiers.IdSha1, spki.PublicKey.GetBytes());
        }
    }
}
