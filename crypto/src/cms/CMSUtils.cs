using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal static class CmsUtilities
    {
        private static readonly HashSet<DerObjectIdentifier> DesAlgorithms = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> ECAlgorithms = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> GostAlgorithms = new HashSet<DerObjectIdentifier>();
        private static readonly HashSet<DerObjectIdentifier> MqvAlgorithms = new HashSet<DerObjectIdentifier>();

        static CmsUtilities()
        {
            DesAlgorithms.Add(OiwObjectIdentifiers.DesCbc);
            DesAlgorithms.Add(Asn1.Pkcs.PkcsObjectIdentifiers.DesEde3Cbc);
            DesAlgorithms.Add(Asn1.Pkcs.PkcsObjectIdentifiers.IdAlgCms3DesWrap);

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

        internal static bool IsDes(DerObjectIdentifier oid) => DesAlgorithms.Contains(oid);

        internal static bool IsEC(DerObjectIdentifier oid) => ECAlgorithms.Contains(oid);

        internal static bool IsGost(DerObjectIdentifier oid) => GostAlgorithms.Contains(oid);

        internal static bool IsMqv(DerObjectIdentifier oid) => MqvAlgorithms.Contains(oid);

        internal static bool IsEquivalent(AlgorithmIdentifier algID1, AlgorithmIdentifier algID2)
        {
            if (algID1 == null || algID2 == null)
                return false;

            return X509Utilities.AreEquivalentAlgorithms(algID1, algID2);
        }

        internal static ContentInfo ReadContentInfo(byte[] input)
        {
            Asn1Object asn1Object = SafeAsn1FromByteArray(input) ?? throw new CmsException("No content found.");

            return SafeGetInstance(asn1Object, ContentInfo.GetInstance);
        }

        internal static ContentInfo ReadContentInfo(Stream input)
        {
            Asn1Object asn1Object = SafeAsn1FromStream(input) ?? throw new CmsException("No content found.");

            return SafeGetInstance(asn1Object, ContentInfo.GetInstance);
        }

        internal static byte[] StreamToByteArray(Stream inStream) => Streams.ReadAll(inStream);

        internal static byte[] StreamToByteArray(Stream inStream, int limit) => Streams.ReadAllLimited(inStream, limit);

        internal static void AddDigestAlgorithms(DigestAlgorithmsBuilder builder, SignerInformation signer)
        {
            builder.Add(signer.DigestAlgorithmID);

            foreach (var counterSigner in signer.GetCounterSignatures())
            {
                builder.Add(counterSigner.DigestAlgorithmID);
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

        internal static Asn1Set ToAsn1Set(this IReadOnlyCollection<Asn1Encodable> elements, bool useDer, bool useDL)
        {
            return useDer
                ? ToDerSet(elements)
                : useDL
                ? ToDLSet(elements)
                : ToBerSet(elements);
        }

        internal static Asn1Set ToAsn1SetOptional(this IReadOnlyCollection<Asn1Encodable> elements, bool useDer,
            bool useDL)
        {
            return elements.Count < 1 ? null : ToAsn1Set(elements, useDer, useDL);
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

        internal static CmsTypedData BindTypedData(DerObjectIdentifier contentType, CmsProcessable processable)
        {
            if (processable == null)
                return new CmsAbsentContent(contentType);

            if (processable is CmsTypedData cmsTypedData && cmsTypedData.ContentType.Equals(contentType))
                return cmsTypedData;

            return new CmsTypedProcessable(contentType, processable);
        }

        internal static CmsTypedData GetTypedData(CmsProcessable processable) =>
            GetTypedData(processable, CmsObjectIdentifiers.Data);

        internal static CmsTypedData GetTypedData(CmsProcessable processable, DerObjectIdentifier defaultContentType)
        {
            if (processable == null)
                return new CmsAbsentContent(defaultContentType);

            if (processable is CmsTypedData cmsTypedData)
                return cmsTypedData;

            return new CmsTypedProcessable(defaultContentType, processable);
        }

        internal static void AddOriginatorInfoToGenerator(BerSequenceGenerator seqGen, OriginatorInfo originatorInfo)
        {
            if (originatorInfo != null)
            {
                seqGen.AddObject(new DerTaggedObject(false, 0, originatorInfo));
            }
        }

        internal static void AddRecipientInfosToGenerator(BerSequenceGenerator authGen,
            Asn1EncodableVector recipientInfos, bool berEncodeRecipientSet)
        {
            recipientInfos.ToAsn1Set(useDer: !berEncodeRecipientSet, useDL: false)
                .EncodeTo(authGen.GetRawOutputStream());
        }

        internal static Asn1Object SafeAsn1FromByteArray(byte[] input)
        {
            try
            {
                return Asn1Object.FromByteArray(input);
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("Exception reading content.", e);
            }
        }

        internal static Asn1Object SafeAsn1FromStream(Stream input)
        {
            try
            {
                return Asn1Object.FromStream(input);
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("Exception reading content.", e);
            }
        }

        /// <exception cref="CmsException"></exception>
        internal static TResult SafeGetContent<TResult>(ContentInfo contentInfo,
            Func<Asn1Encodable, TResult> getInstance)
        {
            var content = contentInfo.Content ?? throw new CmsException("Missing content.");

            return SafeGetInstance(content, getInstance);
        }

        /// <exception cref="CmsException"></exception>
        internal static Asn1OctetString SafeGetEncryptedContent(EncryptedContentInfo encryptedContentInfo) =>
            encryptedContentInfo.EncryptedContent ?? throw new CmsException("Missing content.");

        /// <exception cref="CmsException"></exception>
        internal static TResult SafeGetInstance<T, TResult>(T obj, Func<T, TResult> getInstance)
        {
            try
            {
                return getInstance(obj);
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("Malformed content.", e);
            }
        }

        internal static CmsProcessableByteArray ProcessContentOctetString(ContentInfo contentInfo)
        {
            Asn1OctetString content = CmsUtilities.SafeGetContent(contentInfo, Asn1OctetString.GetInstance);

            return new CmsProcessableByteArray(contentInfo.ContentType, content.GetOctets());
        }

        internal static CmsProcessableByteArray ProcessEncryptedContent(EncryptedContentInfo encryptedContentInfo)
        {
            Asn1OctetString content = CmsUtilities.SafeGetEncryptedContent(encryptedContentInfo);

            return new CmsProcessableByteArray(encryptedContentInfo.ContentType, content.GetOctets());
        }
    }
}
