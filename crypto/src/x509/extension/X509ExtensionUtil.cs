using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509.Extension
{
    // TODO[api] Make static
    public class X509ExtensionUtilities
	{
        internal static Asn1OctetString CalculateKeyIdentifier(AsymmetricKeyParameter publicKey) =>
            CalculateKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

        internal static Asn1OctetString CalculateKeyIdentifier(SubjectPublicKeyInfo spki) =>
            new DerOctetString(CalculateSha1(spki));

        internal static Asn1OctetString CalculateKeyIdentifier(X509Certificate certificate) =>
            CalculateKeyIdentifier(certificate.CertificateStructure.SubjectPublicKeyInfo);

        private static byte[] CalculateSha1(SubjectPublicKeyInfo spki)
        {
            var publicKey = spki.PublicKey;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (publicKey.IsOctetAligned())
                return CalculateSha1(publicKey.GetOctetsSpan());
#endif

            return CalculateSha1(publicKey.GetBytes());
        }

        private static byte[] CalculateSha1(byte[] data) =>
            DigestUtilities.CalculateDigest(OiwObjectIdentifiers.IdSha1, data);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static byte[] CalculateSha1(ReadOnlySpan<byte> data) =>
            DigestUtilities.CalculateDigest(OiwObjectIdentifiers.IdSha1, data);
#endif

        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(AsymmetricKeyParameter publicKey) =>
            new AuthorityKeyIdentifier(CalculateKeyIdentifier(publicKey));

        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(AsymmetricKeyParameter publicKey,
            GeneralNames issuer, BigInteger serialNumber)
        {
            return new AuthorityKeyIdentifier(CalculateKeyIdentifier(publicKey), issuer, new DerInteger(serialNumber));
        }

        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo spki) =>
            new AuthorityKeyIdentifier(CalculateKeyIdentifier(spki));

        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo spki,
            GeneralNames issuer, DerInteger serialNumber)
        {
            return new AuthorityKeyIdentifier(CalculateKeyIdentifier(spki), issuer, serialNumber);
        }

        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(X509Certificate certificate)
        {
            var keyIdentifier = DeriveAuthCertKeyID(certificate);
            var authorityCertIssuer = new GeneralNames(new GeneralName(certificate.IssuerDN));
            var authorityCertSerialNumber = certificate.CertificateStructure.SerialNumber;

            return new AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer, authorityCertSerialNumber);
        }

        public static SubjectKeyIdentifier CreateSubjectKeyIdentifier(AsymmetricKeyParameter publicKey) =>
            new SubjectKeyIdentifier(CalculateKeyIdentifier(publicKey));

        public static SubjectKeyIdentifier CreateSubjectKeyIdentifier(SubjectPublicKeyInfo spki) =>
            new SubjectKeyIdentifier(CalculateKeyIdentifier(spki));

        public static SubjectKeyIdentifier CreateTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo spki)
        {
            byte[] sha1 = CalculateSha1(spki);

            byte[] id = Arrays.CopyOfRange(sha1, sha1.Length - 8, sha1.Length);
            id[0] &= 0x0F;
            id[0] |= 0x40;

            return new SubjectKeyIdentifier(id);
        }

        internal static Asn1OctetString DeriveAuthCertKeyID(X509Certificate authorityCert)
        {
            var subjectKeyIdentifier = GetSubjectKeyIdentifier(authorityCert);
            if (subjectKeyIdentifier != null)
                return DerOctetString.WithContents(subjectKeyIdentifier.GetKeyIdentifier());

            return CalculateKeyIdentifier(authorityCert);
        }

        public static Asn1Object FromExtensionValue(Asn1OctetString extensionValue) =>
            Asn1Object.FromByteArray(extensionValue.GetOctets());

        /// <summary>
        /// Extract the value of the given extension, if it exists.
        /// </summary>
        /// <param name="extensions">The extensions object.</param>
        /// <param name="oid">The object identifier to obtain.</param>
        /// <returns>Asn1Object</returns>
        /// <exception cref="Exception">if the extension cannot be read.</exception>
        public static Asn1Object FromExtensionValue(IX509Extension extensions, DerObjectIdentifier oid) =>
            extensions.GetExtension(oid, Asn1Object.FromByteArray);

        public static AuthorityKeyIdentifier GetAuthorityKeyIdentifier(IX509Extension extension) =>
            extension.GetExtension(X509Extensions.AuthorityKeyIdentifier, AuthorityKeyIdentifier.GetInstance);

        public static SubjectKeyIdentifier GetSubjectKeyIdentifier(IX509Extension extension) =>
            extension.GetExtension(X509Extensions.SubjectKeyIdentifier, SubjectKeyIdentifier.GetInstance);
    }

    // TODO[api] Merge into X509ExtensionUtilities once it's static
    internal static class X509ExtensionUtilitiesExt
    {
        internal static TExtension GetExtension<TExtension>(this IX509Extension extension, DerObjectIdentifier oid,
            Func<byte[], TExtension> constructor)
            where TExtension : class
        {
            Asn1OctetString extensionValue = extension.GetExtensionValue(oid);
            return extensionValue == null ? null : constructor(extensionValue.GetOctets());
        }
    }
}
