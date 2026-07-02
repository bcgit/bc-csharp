using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Nsri;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Crypto.Utilities
{
    /// <summary>
    /// Catalogue of content-encryption algorithm OIDs used where code only needs to identify the parameter form or
    /// block size family for an algorithm.
    /// </summary>
    /// <remarks>
    /// The methods in this class are membership tests only. They do not provide key sizes, JCA names, or provider
    /// registration aliases.
    /// </remarks>
    internal static class OidCatalogue
    {
        private static readonly HashSet<DerObjectIdentifier> CcmAlgs = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> GcmAlgs = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> Cbc128Algs = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> Cbc64Algs = new HashSet<DerObjectIdentifier>();

        static OidCatalogue()
        {
            CcmAlgs.Add(NistObjectIdentifiers.IdAes128Ccm);
            CcmAlgs.Add(NistObjectIdentifiers.IdAes192Ccm);
            CcmAlgs.Add(NistObjectIdentifiers.IdAes256Ccm);
            CcmAlgs.Add(NsriObjectIdentifiers.id_aria128_ccm);
            CcmAlgs.Add(NsriObjectIdentifiers.id_aria192_ccm);
            CcmAlgs.Add(NsriObjectIdentifiers.id_aria256_ccm);
            CcmAlgs.Add(GMObjectIdentifiers.sms4_ccm);

            GcmAlgs.Add(NistObjectIdentifiers.IdAes128Gcm);
            GcmAlgs.Add(NistObjectIdentifiers.IdAes192Gcm);
            GcmAlgs.Add(NistObjectIdentifiers.IdAes256Gcm);
            GcmAlgs.Add(NsriObjectIdentifiers.id_aria128_gcm);
            GcmAlgs.Add(NsriObjectIdentifiers.id_aria192_gcm);
            GcmAlgs.Add(NsriObjectIdentifiers.id_aria256_gcm);
            GcmAlgs.Add(GMObjectIdentifiers.sms4_gcm);

            Cbc128Algs.Add(NistObjectIdentifiers.IdAes128Cbc);
            Cbc128Algs.Add(NistObjectIdentifiers.IdAes192Cbc);
            Cbc128Algs.Add(NistObjectIdentifiers.IdAes256Cbc);
            Cbc128Algs.Add(NttObjectIdentifiers.IdCamellia128Cbc);
            Cbc128Algs.Add(NttObjectIdentifiers.IdCamellia192Cbc);
            Cbc128Algs.Add(NttObjectIdentifiers.IdCamellia256Cbc);
            Cbc128Algs.Add(KisaObjectIdentifiers.IdSeedCbc);
            Cbc128Algs.Add(GMObjectIdentifiers.sms4_cbc);

            Cbc64Algs.Add(OiwObjectIdentifiers.DesCbc);
            Cbc64Algs.Add(PkcsObjectIdentifiers.DesEde3Cbc);
            Cbc64Algs.Add(PkcsObjectIdentifiers.RC2Cbc);
            Cbc64Algs.Add(MiscObjectIdentifiers.cast5CBC);
            Cbc64Algs.Add(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC);
        }

        /// <summary>
        /// Return whether the OID identifies a CCM content-encryption algorithm whose parameters are encoded as
        /// CCMParameters.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known CCM content-encryption algorithm.</returns>
        internal static bool IsCcm(DerObjectIdentifier algorithm) => CcmAlgs.Contains(algorithm);

        /// <summary>
        /// Return whether the OID identifies a GCM content-encryption algorithm whose parameters are encoded as
        /// GCMParameters.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known GCM content-encryption algorithm.</returns>
        public static bool IsGcm(DerObjectIdentifier algorithm) => GcmAlgs.Contains(algorithm);

        /// <summary>
        /// Return whether the OID identifies a CBC content-encryption algorithm with a 128-bit block size and an IV
        /// encoded as an octet string.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known 128-bit block CBC content-encryption algorithm.</returns>
        public static bool IsCbc128(DerObjectIdentifier algorithm) => Cbc128Algs.Contains(algorithm);

        /// <summary>
        /// Return whether the OID identifies a CBC content-encryption algorithm with a 64-bit block size (DES,
        /// triple-DES, RC2, CAST5, IDEA).
        /// </summary>
        /// <remarks>
        /// This is a block-size predicate only: unlike the GCM / CCM / CBC-128 families, the members do not share a
        /// single parameter encoding(RC2 carries RC2CBCParameter, CAST5 carries CAST5CBCParameters, the rest an
        /// octet-string IV), so this test is for code that classifies by block size (e.g.PKCS#7 padded output length)
        /// rather than by parameter form.
        /// </remarks>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known 64-bit block CBC content-encryption algorithm.</returns>
        public static bool IsCbc64(DerObjectIdentifier algorithm) => Cbc64Algs.Contains(algorithm);

        /// <summary>
        /// Return whether the OID identifies the ChaCha20-Poly1305 AEAD content-encryption algorithm.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is ChaCha20-Poly1305.</returns>
        public static bool IsChaCha20Poly1305(DerObjectIdentifier algorithm) =>
            PkcsObjectIdentifiers.IdAlgAeadChaCha20Poly1305.Equals(algorithm);

        /// <summary>
        /// Return whether the OID identifies an AEAD content-encryption algorithm whose parameters are encoded as
        /// GCMParameters or CCMParameters (i.e. a GCM or CCM algorithm). ChaCha20-Poly1305, whose parameters differ, is
        /// not included here; use <see cref="IsAuthEnveloped(DerObjectIdentifier)"/> for the full set of algorithms
        /// usable with CMS AuthEnvelopedData.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known GCM or CCM content-encryption algorithm.</returns>
        public static bool IsAead(DerObjectIdentifier algorithm) => IsGcm(algorithm) || IsCcm(algorithm);

        /// <summary>
        /// Return whether the OID identifies a content-encryption algorithm that provides authenticated encryption and
        /// so can be used with CMS AuthEnvelopedData (RFC 5083): the GCM and CCM families plus ChaCha20-Poly1305.
        /// </summary>
        /// <param name="algorithm">Candidate algorithm OID.</param>
        /// <returns><c>true</c> if the OID is a known AEAD content-encryption algorithm.</returns>
        public static bool IsAuthEnveloped(DerObjectIdentifier algorithm) =>
            IsAead(algorithm) || IsChaCha20Poly1305(algorithm);
    }
}
