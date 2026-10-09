using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cmp
{
    /*
     * RFC 9810 5.3.18: the certHash in a certConf is computed with the hash algorithm the certificate's
     * signatureAlgorithm specifies, or the one specified for hashing certificates signed with it. Where there is
     * neither, the hashAlg field of the CertStatus must name the hash (and the certConf must be cmp2021).
     *
     * The digest algorithm finder answers a different question (the digest CMS pairs with a signature
     * algorithm), so the CMP-specific answers are kept here, and only anything not covered falls through to it.
     */
    internal static class CmpUtilities
    {
        // Signature algorithms with a certHash hash fixed by the algorithm itself or by a CMP specification.
        private static readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> CertHashAlgorithms =
            new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();

        // Signature algorithms with neither, for which the certHash hash must be given explicitly in hashAlg.
        private static readonly HashSet<DerObjectIdentifier> HashAlgRequired = new HashSet<DerObjectIdentifier>();

        static CmpUtilities()
        {
            /*
             * RFC 9481 3.3: EdDSA. RFC 9480 gave EdDSA as an example needing hashAlg; RFC 9810 obsoletes it and
             * defers to RFC 9481 instead. Ed448 uses SHAKE256 with a 512-bit output, which in CMP is plain
             * id-shake256 (RFC 9481 2.2), not the id-shake256-len form CMS uses for Ed448 (RFC 8419).
             */
            AddCertHashAlgorithm(EdECObjectIdentifiers.id_Ed25519, NistObjectIdentifiers.IdSha512);
            AddCertHashAlgorithm(EdECObjectIdentifiers.id_Ed448, NistObjectIdentifiers.IdShake256);

            /*
             * ML-DSA and SLH-DSA: the pre-hash variants specify their hash; the pure variants specify none, and no
             * CMP specification assigns one.
             */
            foreach (MLDsaParameters mlDsa in MLDsaParameters.ByName.Values)
            {
                AddPreHashAlgorithm(mlDsa.Oid, mlDsa.PreHashOid);
            }
            foreach (SlhDsaParameters slhDsa in SlhDsaParameters.ByName.Values)
            {
                AddPreHashAlgorithm(slhDsa.Oid, slhDsa.PreHashOid);
            }

            // Composite ML-DSA: each combination's pre-hash, named by its OID.
            foreach (CompositeMLDsaParameters compositeMLDsa in CompositeMLDsaParameters.ByName.Values)
            {
                AddCertHashAlgorithm(compositeMLDsa.Oid,
                    DigestUtilities.GetObjectIdentifier(compositeMLDsa.PreHashAlgorithm));
            }

            /*
             * XMSS and XMSS^MT (RFC 9802): the hash depends on the key's parameter set, not the signature algorithm.
             *
             * NOTE: HSS/LMS is in the same position, but is left to the digest algorithm finder (SHA-256), which
             * is what it has always used here, and what bc-java sends.
             */
            HashAlgRequired.Add(IanaObjectIdentifiers.id_alg_xmss_hashsig);
            HashAlgRequired.Add(IanaObjectIdentifiers.id_alg_xmssmt_hashsig);
        }

        private static void AddCertHashAlgorithm(DerObjectIdentifier signatureOid, DerObjectIdentifier digestOid) =>
            CertHashAlgorithms.Add(signatureOid, new AlgorithmIdentifier(digestOid));

        private static void AddPreHashAlgorithm(DerObjectIdentifier signatureOid, DerObjectIdentifier preHashOid)
        {
            if (preHashOid != null)
            {
                AddCertHashAlgorithm(signatureOid, preHashOid);
            }
            else
            {
                HashAlgRequired.Add(signatureOid);
            }
        }

        // hashAlg is the hash named by the CertStatus hashAlg field, or null to derive it from signatureAlgorithm.
        internal static byte[] CalculateCertHash(Asn1Encodable asn1Encodable, AlgorithmIdentifier signatureAlgorithm,
            AlgorithmIdentifier hashAlg, IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            var digestAlgorithm = hashAlg ?? FindCertHashAlgorithm(signatureAlgorithm, digestAlgorithmFinder);

            return X509.X509Utilities.CalculateDigest(digestAlgorithm, asn1Encodable);
        }

        internal static AlgorithmIdentifier FindCertHashAlgorithm(AlgorithmIdentifier signatureAlgorithm,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            DerObjectIdentifier signatureOid = signatureAlgorithm.Algorithm;

            if (CertHashAlgorithms.TryGetValue(signatureOid, out var certHashAlgorithm))
                return certHashAlgorithm;

            if (HashAlgRequired.Contains(signatureOid))
            {
                throw new CmpException("certHash for signature algorithm " + signatureOid.GetID() +
                    " requires an explicit hashAlg");
            }

            return digestAlgorithmFinder.Find(signatureAlgorithm)
                ?? throw new CmpException("cannot find digest algorithm from signature algorithm");
        }
    }
}
