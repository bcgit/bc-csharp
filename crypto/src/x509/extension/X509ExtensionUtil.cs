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
    /// <summary>Utility methods for creating and reading common X.509 extension values.</summary>
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

        /// <summary>Create an authority key identifier from the SHA-1 hash of the issuer's public key.</summary>
        /// <param name="publicKey">The issuer's public key.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(AsymmetricKeyParameter publicKey) =>
            new AuthorityKeyIdentifier(CalculateKeyIdentifier(publicKey));

        /// <summary>
        /// Create an authority key identifier from the issuer's public key, issuer name and certificate serial number.
        /// </summary>
        /// <param name="publicKey">The issuer's public key.</param>
        /// <param name="issuer">The issuer's names.</param>
        /// <param name="serialNumber">The serial number of the issuer's certificate.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(AsymmetricKeyParameter publicKey,
            GeneralNames issuer, BigInteger serialNumber)
        {
            return new AuthorityKeyIdentifier(CalculateKeyIdentifier(publicKey), issuer, new DerInteger(serialNumber));
        }

        /// <summary>Create an authority key identifier from the issuer's subject key identifier.</summary>
        /// <param name="ski">The issuer's subject key identifier.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectKeyIdentifier ski) =>
            new AuthorityKeyIdentifier(DerOctetString.WithContents(ski.GetKeyIdentifier()));

        /// <summary>Create an authority key identifier from the SHA-1 hash of the issuer's public key.</summary>
        /// <param name="spki">The issuer's public key info.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo spki) =>
            new AuthorityKeyIdentifier(CalculateKeyIdentifier(spki));

        /// <summary>
        /// Create an authority key identifier from the issuer's public key, issuer name and certificate serial number.
        /// </summary>
        /// <param name="spki">The issuer's public key info.</param>
        /// <param name="issuer">The issuer's names.</param>
        /// <param name="serialNumber">The serial number of the issuer's certificate.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(SubjectPublicKeyInfo spki,
            GeneralNames issuer, DerInteger serialNumber)
        {
            return new AuthorityKeyIdentifier(CalculateKeyIdentifier(spki), issuer, serialNumber);
        }

        /// <summary>
        /// Create an authority key identifier for the issuer certificate, including its name and serial number.
        /// </summary>
        /// <param name="certificate">The issuer's certificate.</param>
        public static AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(X509Certificate certificate)
        {
            var keyIdentifier = DeriveAuthCertKeyID(certificate);
            var authorityCertIssuer = new GeneralNames(new GeneralName(certificate.IssuerDN));
            var authorityCertSerialNumber = certificate.CertificateStructure.SerialNumber;

            return new AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer, authorityCertSerialNumber);
        }

        /// <summary>Create a subject key identifier from the SHA-1 hash of the public key.</summary>
        /// <param name="publicKey">The public key.</param>
        public static SubjectKeyIdentifier CreateSubjectKeyIdentifier(AsymmetricKeyParameter publicKey) =>
            new SubjectKeyIdentifier(CalculateKeyIdentifier(publicKey));

        /// <summary>Create a subject key identifier from the SHA-1 hash of the public key.</summary>
        /// <param name="spki">The public key info.</param>
        public static SubjectKeyIdentifier CreateSubjectKeyIdentifier(SubjectPublicKeyInfo spki) =>
            new SubjectKeyIdentifier(CalculateKeyIdentifier(spki));

        /// <summary>
        /// Create a subject key identifier from the low-order 64 bits of the SHA-1 hash of the public key, with the
        /// four high-order bits set to 0100 (RFC 5280, 4.2.1.2, method 2).
        /// </summary>
        /// <param name="spki">The public key info.</param>
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

        /// <summary>Parse the value of an extension.</summary>
        /// <param name="extensionValue">The octet string holding the extension value.</param>
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

        /// <summary>Return the authority key identifier extension, if present.</summary>
        /// <param name="extension">The object carrying the extensions.</param>
        /// <returns>The authority key identifier, or null if the extension is not present.</returns>
        public static AuthorityKeyIdentifier GetAuthorityKeyIdentifier(IX509Extension extension) =>
            extension.GetExtension(X509Extensions.AuthorityKeyIdentifier, AuthorityKeyIdentifier.GetInstance);

        /// <summary>Return the subject key identifier extension, if present.</summary>
        /// <param name="extension">The object carrying the extensions.</param>
        /// <returns>The subject key identifier, or null if the extension is not present.</returns>
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
            Asn1OctetString extensionValue = extension?.GetExtensionValue(oid);
            return extensionValue == null ? null : constructor(extensionValue.GetOctets());
        }

        internal static TExtension GetExtension<TExtension>(this X509Extensions extensions,
            DerObjectIdentifier oid, Func<byte[], TExtension> constructor)
            where TExtension : class
        {
            Asn1OctetString extensionValue = extensions?.GetExtensionValue(oid);
            return extensionValue == null ? null : constructor(extensionValue.GetOctets());
        }

        internal static TExtension GetExtension<TExtension>(this Extensions extensions,
            DerObjectIdentifier oid, Func<byte[], TExtension> constructor)
            where TExtension : class
        {
            Asn1OctetString extensionValue = extensions?.GetExtensionValue(oid);
            return extensionValue == null ? null : constructor(extensionValue.GetOctets());
        }
    }
}
