using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Tsp
{
    public enum Resolution
    {
        R_SECONDS, R_TENTHS_OF_SECONDS, R_HUNDREDTHS_OF_SECONDS, R_MILLISECONDS
    }

    public class TspUtil
    {
        // TODO Migrate this information to DigestUtilities
        private static readonly Dictionary<DerObjectIdentifier, int> DigestLengths =
            new Dictionary<DerObjectIdentifier, int>();

        static TspUtil()
        {
            DigestLengths.Add(PkcsObjectIdentifiers.MD5, 16);
            DigestLengths.Add(OiwObjectIdentifiers.IdSha1, 20);
            DigestLengths.Add(NistObjectIdentifiers.IdSha224, 28);
            DigestLengths.Add(NistObjectIdentifiers.IdSha256, 32);
            DigestLengths.Add(NistObjectIdentifiers.IdSha384, 48);
            DigestLengths.Add(NistObjectIdentifiers.IdSha512, 64);
            DigestLengths.Add(NistObjectIdentifiers.IdSha3_224, 28);
            DigestLengths.Add(NistObjectIdentifiers.IdSha3_256, 32);
            DigestLengths.Add(NistObjectIdentifiers.IdSha3_384, 48);
            DigestLengths.Add(NistObjectIdentifiers.IdSha3_512, 64);
            DigestLengths.Add(TeleTrusTObjectIdentifiers.RipeMD128, 16);
            DigestLengths.Add(TeleTrusTObjectIdentifiers.RipeMD160, 20);
            DigestLengths.Add(TeleTrusTObjectIdentifiers.RipeMD256, 32);
            DigestLengths.Add(CryptoProObjectIdentifiers.GostR3411, 32);
            DigestLengths.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, 32);
            DigestLengths.Add(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, 64);
            DigestLengths.Add(GMObjectIdentifiers.sm3, 32);
        }

        /// <summary>
        /// Fetches the signature time-stamp attributes from a SignerInformation object.
        /// </summary>
        /// <remarks>
        /// Checks that the MessageImprint for each time-stamp matches the signature field. (see RFC 3161 Appendix A).
        /// </remarks>
        /// <param name="signerInfo">A <see cref="SignerInformation"/> to search for time-stamps.</param>
        /// <returns>A list of <see cref="TimeStampToken"/> objects.</returns>
        /// <exception cref="TspValidationException"/>
        public static IList<TimeStampToken> GetSignatureTimestamps(SignerInformation signerInfo)
        {
            var timestamps = new List<TimeStampToken>();

            Asn1.Cms.AttributeTable unsignedAttributes = signerInfo.UnsignedAttributes;
            if (unsignedAttributes != null)
            {
                foreach (Asn1.Cms.Attribute tsAttr in unsignedAttributes.GetAll(
                    PkcsObjectIdentifiers.IdAASignatureTimeStampToken))
                {
                    foreach (Asn1Encodable asn1 in tsAttr.AttrValues)
                    {
                        try
                        {
                            Asn1.Cms.ContentInfo contentInfo = Asn1.Cms.ContentInfo.GetInstance(
                                asn1.ToAsn1Object());
                            TimeStampToken timeStampToken = new TimeStampToken(contentInfo);
                            TimeStampTokenInfo tstInfo = timeStampToken.TimeStampInfo;

                            byte[] expectedDigest = DigestUtilities.CalculateDigest(tstInfo.HashAlgorithm,
                                signerInfo.GetSignature());

                            if (!Arrays.FixedTimeEquals(expectedDigest, tstInfo.MessageImprintDigest.GetOctets()))
                                throw new TspValidationException("Incorrect digest in message imprint");

                            timestamps.Add(timeStampToken);
                        }
                        catch (SecurityUtilityException)
                        {
                            throw new TspValidationException("Unknown hash algorithm specified in timestamp");
                        }
                        catch (Exception)
                        {
                            throw new TspValidationException("Timestamp could not be parsed");
                        }
                    }
                }
            }

            return timestamps;
        }

        /// <summary>
        /// Validate the passed in certificate as being of the correct type to be used for time stamping.
        /// </summary>
        /// <remarks>
        /// To be valid it must have an ExtendedKeyUsage extension which has a key purpose identifier of
        /// id-kp-timeStamping.
        /// </remarks>
        /// <param name="cert">The certificate of interest.</param>
        /// <exception cref="TspValidationException">
        /// If the certicate fails on one of the check points.
        /// </exception>
        public static void ValidateCertificate(X509Certificate cert)
        {
            if (cert.Version != 3)
                throw new ArgumentException("Certificate must have an ExtendedKeyUsage extension.");

            ExtendedKeyUsage eku;
            try
            {
                eku = cert.GetExtension(X509Extensions.ExtendedKeyUsage, ExtendedKeyUsage.GetInstance);
            }
            catch (Exception)
            {
                throw new TspValidationException("cannot process ExtendedKeyUsage extension");
            }

            if (eku == null)
                throw new TspValidationException("Certificate must have an ExtendedKeyUsage extension.");

            if (!cert.GetCriticalExtensionOids().Contains(X509Extensions.ExtendedKeyUsage.Id))
                throw new TspValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");

            if (!eku.HasKeyPurposeId(KeyPurposeID.id_kp_timeStamping) || eku.Count != 1)
                throw new TspValidationException("ExtendedKeyUsage not solely time stamping.");
        }

        internal static int GetDigestLength(DerObjectIdentifier digestAlgOid)
        {
            if (!DigestLengths.TryGetValue(digestAlgOid, out int length))
                throw new TspException("digest algorithm cannot be found.");

            return length;
        }

        internal static IList<DerObjectIdentifier> GetExtensionOids(X509Extensions extensions)
        {
            return extensions == null
                ? new List<DerObjectIdentifier>()
                : new List<DerObjectIdentifier>(extensions.GetExtensionOids());
        }

        internal static DateTime WithResolution(DateTime dateTime, Resolution resolution)
        {
            switch (resolution)
            {
            case Resolution.R_SECONDS:
                return DateTimeUtilities.WithPrecisionSecond(dateTime);
            case Resolution.R_TENTHS_OF_SECONDS:
                return DateTimeUtilities.WithPrecisionDecisecond(dateTime);
            case Resolution.R_HUNDREDTHS_OF_SECONDS:
                return DateTimeUtilities.WithPrecisionCentisecond(dateTime);
            case Resolution.R_MILLISECONDS:
                return DateTimeUtilities.WithPrecisionMillisecond(dateTime);
            default:
                throw new ArgumentException("Invalid enum value", nameof(resolution));
            }
        }
    }
}
