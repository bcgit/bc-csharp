using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The Composite ML-DSA algorithm combinations defined by
    /// <a href="https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/">Composite ML-DSA for use
    /// in X.509 Public Key Infrastructure and CMS</a>.
    /// </summary>
    /// <remarks>
    /// Each combination pairs an ML-DSA parameter set with a traditional signature algorithm, and fixes the
    /// pre-hash used to build the message representative plus the domain separator that binds a signature to
    /// exactly one combination. The IANA-assigned identifiers live under the <c>1.3.6.1.5.5.7.6</c> arc.
    /// </remarks>
    public sealed class CompositeMLDsaParameters
    {
        /// <summary>The kind of traditional key a combination pairs ML-DSA with.</summary>
        internal enum TraditionalKeyType
        {
            Rsa,
            ECDsa,
            Ed25519,
            Ed448,
        }

        private const string Sha256 = "SHA-256";
        private const string Sha384 = "SHA-384";
        private const string Sha512 = "SHA-512";
        private const string Shake256 = "SHAKE256";

        /// <summary>ML-DSA-44 with RSASSA-PSS (2048-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa44_RSA2048_PSS_SHA256 = CreateRsa(
            "MLDSA44-RSA2048-PSS-SHA256", IanaObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,
            MLDsaParameters.ml_dsa_44, Sha256, "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", "SHA-256withRSAandMGF1",
            rsaKeySize: 2048);

        /// <summary>ML-DSA-44 with RSASSA-PKCS1-v1_5 (2048-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa44_RSA2048_PKCS15_SHA256 = CreateRsa(
            "MLDSA44-RSA2048-PKCS15-SHA256", IanaObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256,
            MLDsaParameters.ml_dsa_44, Sha256, "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", "SHA-256withRSA",
            rsaKeySize: 2048);

        /// <summary>ML-DSA-44 with Ed25519.</summary>
        public static readonly CompositeMLDsaParameters MLDsa44_Ed25519_SHA512 = Create(
            "MLDSA44-Ed25519-SHA512", IanaObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, MLDsaParameters.ml_dsa_44,
            Sha512, "COMPSIG-MLDSA44-Ed25519-SHA512", "Ed25519", TraditionalKeyType.Ed25519);

        /// <summary>ML-DSA-44 with ECDSA on NIST P-256.</summary>
        public static readonly CompositeMLDsaParameters MLDsa44_ECDsa_P256_SHA256 = CreateECDsa(
            "MLDSA44-ECDSA-P256-SHA256", IanaObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256,
            MLDsaParameters.ml_dsa_44, Sha256, "COMPSIG-MLDSA44-ECDSA-P256-SHA256", "SHA-256withECDSA",
            SecObjectIdentifiers.SecP256r1);

        /// <summary>ML-DSA-65 with RSASSA-PSS (3072-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_RSA3072_PSS_SHA512 = CreateRsa(
            "MLDSA65-RSA3072-PSS-SHA512", IanaObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", "SHA-256withRSAandMGF1",
            rsaKeySize: 3072);

        /// <summary>ML-DSA-65 with RSASSA-PKCS1-v1_5 (3072-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_RSA3072_PKCS15_SHA512 = CreateRsa(
            "MLDSA65-RSA3072-PKCS15-SHA512", IanaObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", "SHA-256withRSA",
            rsaKeySize: 3072);

        /// <summary>ML-DSA-65 with RSASSA-PSS (4096-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_RSA4096_PSS_SHA512 = CreateRsa(
            "MLDSA65-RSA4096-PSS-SHA512", IanaObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", "SHA-384withRSAandMGF1",
            rsaKeySize: 4096);

        /// <summary>ML-DSA-65 with RSASSA-PKCS1-v1_5 (4096-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_RSA4096_PKCS15_SHA512 = CreateRsa(
            "MLDSA65-RSA4096-PKCS15-SHA512", IanaObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", "SHA-384withRSA",
            rsaKeySize: 4096);

        /// <summary>ML-DSA-65 with ECDSA on NIST P-256.</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_ECDsa_P256_SHA512 = CreateECDsa(
            "MLDSA65-ECDSA-P256-SHA512", IanaObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-ECDSA-P256-SHA512", "SHA-256withECDSA",
            SecObjectIdentifiers.SecP256r1);

        /// <summary>ML-DSA-65 with ECDSA on NIST P-384.</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_ECDsa_P384_SHA512 = CreateECDsa(
            "MLDSA65-ECDSA-P384-SHA512", IanaObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-ECDSA-P384-SHA512", "SHA-384withECDSA",
            SecObjectIdentifiers.SecP384r1);

        /// <summary>ML-DSA-65 with ECDSA on brainpoolP256r1.</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_ECDsa_brainpoolP256r1_SHA512 = CreateECDsa(
            "MLDSA65-ECDSA-brainpoolP256r1-SHA512", IanaObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512,
            MLDsaParameters.ml_dsa_65, Sha512, "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", "SHA-256withECDSA",
            TeleTrusTObjectIdentifiers.BrainpoolP256R1);

        /// <summary>ML-DSA-65 with Ed25519.</summary>
        public static readonly CompositeMLDsaParameters MLDsa65_Ed25519_SHA512 = Create(
            "MLDSA65-Ed25519-SHA512", IanaObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, MLDsaParameters.ml_dsa_65,
            Sha512, "COMPSIG-MLDSA65-Ed25519-SHA512", "Ed25519", TraditionalKeyType.Ed25519);

        /// <summary>ML-DSA-87 with ECDSA on NIST P-384.</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_ECDsa_P384_SHA512 = CreateECDsa(
            "MLDSA87-ECDSA-P384-SHA512", IanaObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512,
            MLDsaParameters.ml_dsa_87, Sha512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512", "SHA-384withECDSA",
            SecObjectIdentifiers.SecP384r1);

        /// <summary>ML-DSA-87 with ECDSA on brainpoolP384r1.</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_ECDsa_brainpoolP384r1_SHA512 = CreateECDsa(
            "MLDSA87-ECDSA-brainpoolP384r1-SHA512", IanaObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512,
            MLDsaParameters.ml_dsa_87, Sha512, "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", "SHA-384withECDSA",
            TeleTrusTObjectIdentifiers.BrainpoolP384R1);

        /// <summary>ML-DSA-87 with Ed448.</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_Ed448_SHAKE256 = Create(
            "MLDSA87-Ed448-SHAKE256", IanaObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, MLDsaParameters.ml_dsa_87,
            Shake256, "COMPSIG-MLDSA87-Ed448-SHAKE256", "Ed448", TraditionalKeyType.Ed448);

        /// <summary>ML-DSA-87 with RSASSA-PSS (3072-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_RSA3072_PSS_SHA512 = CreateRsa(
            "MLDSA87-RSA3072-PSS-SHA512", IanaObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512,
            MLDsaParameters.ml_dsa_87, Sha512, "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", "SHA-256withRSAandMGF1",
            rsaKeySize: 3072);

        /// <summary>ML-DSA-87 with RSASSA-PSS (4096-bit).</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_RSA4096_PSS_SHA512 = CreateRsa(
            "MLDSA87-RSA4096-PSS-SHA512", IanaObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512,
            MLDsaParameters.ml_dsa_87, Sha512, "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", "SHA-384withRSAandMGF1",
            rsaKeySize: 4096);

        /// <summary>ML-DSA-87 with ECDSA on NIST P-521.</summary>
        public static readonly CompositeMLDsaParameters MLDsa87_ECDsa_P521_SHA512 = CreateECDsa(
            "MLDSA87-ECDSA-P521-SHA512", IanaObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512,
            MLDsaParameters.ml_dsa_87, Sha512, "COMPSIG-MLDSA87-ECDSA-P521-SHA512", "SHA-512withECDSA",
            SecObjectIdentifiers.SecP521r1);

        private static readonly CompositeMLDsaParameters[] All =
        {
            MLDsa44_RSA2048_PSS_SHA256,
            MLDsa44_RSA2048_PKCS15_SHA256,
            MLDsa44_Ed25519_SHA512,
            MLDsa44_ECDsa_P256_SHA256,
            MLDsa65_RSA3072_PSS_SHA512,
            MLDsa65_RSA3072_PKCS15_SHA512,
            MLDsa65_RSA4096_PSS_SHA512,
            MLDsa65_RSA4096_PKCS15_SHA512,
            MLDsa65_ECDsa_P256_SHA512,
            MLDsa65_ECDsa_P384_SHA512,
            MLDsa65_ECDsa_brainpoolP256r1_SHA512,
            MLDsa65_Ed25519_SHA512,
            MLDsa87_ECDsa_P384_SHA512,
            MLDsa87_ECDsa_brainpoolP384r1_SHA512,
            MLDsa87_Ed448_SHAKE256,
            MLDsa87_RSA3072_PSS_SHA512,
            MLDsa87_RSA4096_PSS_SHA512,
            MLDsa87_ECDsa_P521_SHA512,
        };

        internal static readonly IDictionary<string, CompositeMLDsaParameters> ByName = CreateByName();

        internal static readonly IDictionary<DerObjectIdentifier, CompositeMLDsaParameters> ByOid = CreateByOid();

        private static IDictionary<string, CompositeMLDsaParameters> CreateByName()
        {
            var d = new Dictionary<string, CompositeMLDsaParameters>();
            foreach (var parameters in All)
            {
                d.Add(parameters.Name, parameters);
            }
            return CollectionUtilities.ReadOnly(d);
        }

        private static IDictionary<DerObjectIdentifier, CompositeMLDsaParameters> CreateByOid()
        {
            var d = new Dictionary<DerObjectIdentifier, CompositeMLDsaParameters>();
            foreach (var parameters in All)
            {
                d.Add(parameters.Oid, parameters);
            }
            return CollectionUtilities.ReadOnly(d);
        }

        private static CompositeMLDsaParameters Create(string name, DerObjectIdentifier oid,
            MLDsaParameters mlDsaParameters, string preHashAlgorithm, string domain,
            string traditionalSignatureAlgorithm, TraditionalKeyType traditionalKeyType)
        {
            return new CompositeMLDsaParameters(name, oid, mlDsaParameters, preHashAlgorithm, domain,
                traditionalSignatureAlgorithm, traditionalKeyType, rsaKeySize: 0, curveOid: null);
        }

        private static CompositeMLDsaParameters CreateECDsa(string name, DerObjectIdentifier oid,
            MLDsaParameters mlDsaParameters, string preHashAlgorithm, string domain,
            string traditionalSignatureAlgorithm, DerObjectIdentifier curveOid)
        {
            return new CompositeMLDsaParameters(name, oid, mlDsaParameters, preHashAlgorithm, domain,
                traditionalSignatureAlgorithm, TraditionalKeyType.ECDsa, rsaKeySize: 0, curveOid: curveOid);
        }

        private static CompositeMLDsaParameters CreateRsa(string name, DerObjectIdentifier oid,
            MLDsaParameters mlDsaParameters, string preHashAlgorithm, string domain,
            string traditionalSignatureAlgorithm, int rsaKeySize)
        {
            return new CompositeMLDsaParameters(name, oid, mlDsaParameters, preHashAlgorithm, domain,
                traditionalSignatureAlgorithm, TraditionalKeyType.Rsa, rsaKeySize: rsaKeySize, curveOid: null);
        }

        private readonly string m_name;
        private readonly DerObjectIdentifier m_oid;
        private readonly MLDsaParameters m_mlDsaParameters;
        private readonly string m_preHashAlgorithm;
        private readonly byte[] m_domain;
        private readonly string m_traditionalSignatureAlgorithm;
        private readonly TraditionalKeyType m_traditionalKeyType;
        private readonly int m_rsaKeySize;
        private readonly DerObjectIdentifier m_curveOid;

        private CompositeMLDsaParameters(string name, DerObjectIdentifier oid, MLDsaParameters mlDsaParameters,
            string preHashAlgorithm, string domain, string traditionalSignatureAlgorithm,
            TraditionalKeyType traditionalKeyType, int rsaKeySize, DerObjectIdentifier curveOid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
            m_mlDsaParameters = mlDsaParameters ?? throw new ArgumentNullException(nameof(mlDsaParameters));
            m_preHashAlgorithm = preHashAlgorithm;
            m_domain = Strings.ToByteArray(domain);
            m_traditionalSignatureAlgorithm = traditionalSignatureAlgorithm;
            m_traditionalKeyType = traditionalKeyType;
            m_rsaKeySize = rsaKeySize;
            m_curveOid = curveOid;
        }

        /// <summary>The standard algorithm name (e.g. <c>MLDSA65-ECDSA-P384-SHA512</c>).</summary>
        public string Name => m_name;

        /// <summary>The ML-DSA parameter set used by the post-quantum component.</summary>
        public MLDsaParameters MLDsaParameters => m_mlDsaParameters;

        /// <summary>
        /// The name of the traditional component's signature algorithm, as understood by
        /// <c>SignerUtilities</c> (e.g. <c>SHA-384withECDSA</c>).
        /// </summary>
        public string TraditionalSignatureAlgorithm => m_traditionalSignatureAlgorithm;

        /// <summary>
        /// The name of the pre-hash this combination applies to the message, as understood by
        /// <c>DigestUtilities</c> (e.g. <c>SHA-512</c>). A caller pre-hashing out of band — see the
        /// pre-hashed mode of <c>CompositeMLDsaSigner</c> — must use this digest.
        /// </summary>
        public string PreHashAlgorithm => m_preHashAlgorithm;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier CurveOid => m_curveOid;

        internal int RsaKeySize => m_rsaKeySize;

        internal TraditionalKeyType KeyType => m_traditionalKeyType;

        /// <summary>The length of the ML-DSA component of a composite public key or signature.</summary>
        internal int MLDsaPublicKeyLength => m_mlDsaParameters.ParameterSet.PublicKeyLength;

        internal int MLDsaSignatureLength => m_mlDsaParameters.ParameterSet.SignatureLength;

        internal int MLDsaSeedLength => m_mlDsaParameters.ParameterSet.SeedLength;

        /// <summary>
        /// The domain separator that binds a signature to this combination; it is both the ML-DSA component's
        /// context string and part of the message representative.
        /// </summary>
        internal byte[] GetDomain() => Arrays.Clone(m_domain);

        /// <summary>Returns the algorithm name (see <see cref="Name"/>).</summary>
        public override string ToString() => Name;
    }
}
