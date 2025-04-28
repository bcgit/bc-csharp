using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal static class CmsUtilities
    {
        // TODO Is there a .NET equivalent to this?
        //		private static readonly Runtime RUNTIME = Runtime.getRuntime();

        private static readonly HashSet<DerObjectIdentifier> ECAlgorithms = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> GostAlgorithms = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> MqvAlgorithms = new HashSet<DerObjectIdentifier>();

        static CmsUtilities()
        {
            ECAlgorithms.Add(X9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme);
            ECAlgorithms.Add(X9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme);
            ECAlgorithms.Add(SecObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme);

            GostAlgorithms.Add(CryptoProObjectIdentifiers.GostR3410x2001CryptoProESDH);
            GostAlgorithms.Add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
            GostAlgorithms.Add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);

            MqvAlgorithms.Add(X9ObjectIdentifiers.MqvSinglePassSha1KdfScheme);
            MqvAlgorithms.Add(SecObjectIdentifiers.mqvSinglePass_sha224kdf_scheme);
            MqvAlgorithms.Add(SecObjectIdentifiers.mqvSinglePass_sha256kdf_scheme);
            MqvAlgorithms.Add(SecObjectIdentifiers.mqvSinglePass_sha384kdf_scheme);
            MqvAlgorithms.Add(SecObjectIdentifiers.mqvSinglePass_sha512kdf_scheme);
        }

        internal static byte[] GetByteArray(CmsProcessable content)
        {
            if (content == null)
                return Array.Empty<byte>();

            if (content is CmsProcessableByteArray byteArray)
                return byteArray.GetByteArray();

            using (var buf = new MemoryStream())
            {
                content.Write(buf);
                return buf.ToArray();
            }
        }

        internal static bool IsEC(DerObjectIdentifier oid) => ECAlgorithms.Contains(oid);

        internal static bool IsGost(DerObjectIdentifier oid) => GostAlgorithms.Contains(oid);

        internal static bool IsMqv(DerObjectIdentifier oid) => MqvAlgorithms.Contains(oid);

        internal static int MaximumMemory
        {
            get
            {
                // TODO Is there a .NET equivalent to this?
                long maxMem = int.MaxValue;//RUNTIME.maxMemory();

                if (maxMem > int.MaxValue)
                {
                    return int.MaxValue;
                }

                return (int)maxMem;
            }
        }

        internal static ContentInfo ReadContentInfo(byte[] input)
        {
            using (var asn1In = new Asn1InputStream(input))
            {
                return ReadContentInfo(asn1In);
            }
        }

        internal static ContentInfo ReadContentInfo(Stream input)
        {
            using (var asn1In = new Asn1InputStream(input, MaximumMemory, leaveOpen: true))
            {
                return ReadContentInfo(asn1In);
            }
        }

        private static ContentInfo ReadContentInfo(Asn1InputStream asn1In)
        {
            try
            {
                return ContentInfo.GetInstance(asn1In.ReadObject());
            }
            catch (IOException e)
            {
                throw new CmsException("IOException reading content.", e);
            }
            catch (InvalidCastException e)
            {
                throw new CmsException("Malformed content.", e);
            }
            catch (ArgumentException e)
            {
                throw new CmsException("Malformed content.", e);
            }
        }

        internal static byte[] StreamToByteArray(Stream inStream) => Streams.ReadAll(inStream);

        internal static byte[] StreamToByteArray(Stream inStream, int limit) => Streams.ReadAllLimited(inStream, limit);

        internal static void AddDigestAlgs(ICollection<AlgorithmIdentifier> digestAlgs, SignerInformation signer,
            IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            digestAlgs.Add(CmsSignedHelper.FixDigestAlgID(signer.DigestAlgorithmID, digestAlgorithmFinder));

            foreach (var counterSigner in signer.GetCounterSignatures())
            {
                digestAlgs.Add(CmsSignedHelper.FixDigestAlgID(counterSigner.DigestAlgorithmID, digestAlgorithmFinder));
            }
        }

        internal static IssuerAndSerialNumber GetIssuerAndSerialNumber(TbsCertificateStructure c) =>
            new IssuerAndSerialNumber(c.Issuer, c.SerialNumber);

        internal static IssuerAndSerialNumber GetIssuerAndSerialNumber(X509CertificateStructure c) =>
            GetIssuerAndSerialNumber(c.TbsCertificate);

        internal static IssuerAndSerialNumber GetIssuerAndSerialNumber(X509Certificate c) =>
            GetIssuerAndSerialNumber(c.TbsCertificate);

        internal static SignerIdentifier GetSignerIdentifier(X509Certificate c) =>
            new SignerIdentifier(GetIssuerAndSerialNumber(c));

        internal static SignerIdentifier GetSignerIdentifier(byte[] subjectKeyIdentifier) =>
            new SignerIdentifier(new SubjectKeyIdentifier(subjectKeyIdentifier));

        internal static Asn1.Cms.AttributeTable ParseAttributeTable(Asn1SetParser parser)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            IAsn1Convertible o;
            while ((o = parser.ReadObject()) != null)
            {
                Asn1SequenceParser seq = (Asn1SequenceParser)o;

                v.Add(seq.ToAsn1Object());
            }

            return new Asn1.Cms.AttributeTable(v);
        }

        internal static void CollectAttributeCertificate(List<Asn1Encodable> result,
            X509V2AttributeCertificate attrCert)
        {
            result.Add(new DerTaggedObject(false, 2, attrCert.AttributeCertificate));
        }

        internal static void CollectAttributeCertificates(List<Asn1Encodable> result,
            IStore<X509V2AttributeCertificate> attrCertStore)
        {
            if (attrCertStore != null)
            {
                foreach (var attrCert in attrCertStore.EnumerateMatches(null))
                {
                    CollectAttributeCertificate(result, attrCert);
                }
            }
        }

        internal static void CollectCertificate(List<Asn1Encodable> result, X509Certificate cert)
        {
            result.Add(cert.CertificateStructure);
        }

        internal static void CollectCertificates(List<Asn1Encodable> result, IStore<X509Certificate> certStore)
        {
            if (certStore != null)
            {
                foreach (var cert in certStore.EnumerateMatches(null))
                {
                    CollectCertificate(result, cert);
                }
            }
        }

        internal static void CollectCrl(List<Asn1Encodable> result, X509Crl crl)
        {
            result.Add(crl.CertificateList);
        }

        internal static void CollectCrls(List<Asn1Encodable> result, IStore<X509Crl> crlStore)
        {
            if (crlStore != null)
            {
                foreach (var crl in crlStore.EnumerateMatches(null))
                {
                    CollectCrl(result, crl);
                }
            }
        }

        internal static void CollectOtherRevocationInfo(List<Asn1Encodable> result,
            OtherRevocationInfoFormat otherRevocationInfo)
        {
            ValidateOtherRevocationInfo(otherRevocationInfo);

            result.Add(new DerTaggedObject(false, 1, otherRevocationInfo));
        }

        internal static void CollectOtherRevocationInfo(List<Asn1Encodable> result,
            DerObjectIdentifier otherRevInfoFormat, Asn1Encodable otherRevInfo)
        {
            CollectOtherRevocationInfo(result, new OtherRevocationInfoFormat(otherRevInfoFormat, otherRevInfo));
        }

        internal static void CollectOtherRevocationInfos(List<Asn1Encodable> result,
            IStore<OtherRevocationInfoFormat> otherRevocationInfoStore)
        {
            if (otherRevocationInfoStore != null)
            {
                foreach (var otherRevocationInfo in otherRevocationInfoStore.EnumerateMatches(null))
                {
                    CollectOtherRevocationInfo(result, otherRevocationInfo);
                }
            }
        }

        internal static void CollectOtherRevocationInfos(List<Asn1Encodable> result,
            DerObjectIdentifier otherRevInfoFormat, IStore<Asn1Encodable> otherRevInfoStore)
        {
            if (otherRevInfoStore != null && otherRevInfoFormat != null)
            {
                foreach (var otherRevInfo in otherRevInfoStore.EnumerateMatches(null))
                {
                    CollectOtherRevocationInfo(result, otherRevInfoFormat, otherRevInfo);
                }
            }
        }

        internal static Asn1Set ToBerSet(this IReadOnlyCollection<Asn1Encodable> elements) =>
            BerSet.FromCollection(elements);

        internal static Asn1Set ToDerSet(this IReadOnlyCollection<Asn1Encodable> elements) =>
            DerSet.FromCollection(elements);

        internal static Asn1Set ToDLSet(this IReadOnlyCollection<Asn1Encodable> elements) =>
            DLSet.FromCollection(elements);

        internal static void ValidateOtherRevocationInfo(OtherRevocationInfoFormat otherRevocationInfo)
        {
            if (CmsObjectIdentifiers.id_ri_ocsp_response.Equals(otherRevocationInfo.InfoFormat))
            {
                OcspResponse ocspResponse = OcspResponse.GetInstance(otherRevocationInfo.Info);

                if (!ocspResponse.ResponseStatus.HasValue(OcspResponseStatus.Successful))
                    throw new ArgumentException("cannot add unsuccessful OCSP response to CMS SignedData");
            }
        }
    }
}
