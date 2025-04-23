using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509
{
    internal class X509SignatureUtilities
	{
		/**
		 * Return the digest algorithm using one of the standard JCA string
		 * representations rather than the algorithm identifier (if possible).
		 */
		private static string GetDigestName(DerObjectIdentifier digestAlgOid)
		{
			/*
			 * Note that this can't simply redirect to DigestUtilities because I think the Asn1Signature stuff
			 * depends on particular digest names in some cases (e.g. non-hyphenated SHA algorithms).
			 */

			if (PkcsObjectIdentifiers.MD5.Equals(digestAlgOid))
				return "MD5";

			if (OiwObjectIdentifiers.IdSha1.Equals(digestAlgOid))
				return "SHA1";

			if (NistObjectIdentifiers.IdSha224.Equals(digestAlgOid))
				return "SHA224";

			if (NistObjectIdentifiers.IdSha256.Equals(digestAlgOid))
				return "SHA256";

			if (NistObjectIdentifiers.IdSha384.Equals(digestAlgOid))
				return "SHA384";

			if (NistObjectIdentifiers.IdSha512.Equals(digestAlgOid))
				return "SHA512";

            if (NistObjectIdentifiers.IdSha512_224.Equals(digestAlgOid))
                return "SHA512(224)";

            if (NistObjectIdentifiers.IdSha512_256.Equals(digestAlgOid))
                return "SHA512(256)";

            if (TeleTrusTObjectIdentifiers.RipeMD128.Equals(digestAlgOid))
				return "RIPEMD128";

			if (TeleTrusTObjectIdentifiers.RipeMD160.Equals(digestAlgOid))
				return "RIPEMD160";

			if (TeleTrusTObjectIdentifiers.RipeMD256.Equals(digestAlgOid))
				return "RIPEMD256";

			if (CryptoProObjectIdentifiers.GostR3411.Equals(digestAlgOid))
				return "GOST3411";

            if (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Equals(digestAlgOid))
                return "GOST3411-2012-256";

            if (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Equals(digestAlgOid))
                return "GOST3411-2012-512";

            return digestAlgOid.GetID();
		}

        internal static string GetSignatureName(AlgorithmIdentifier sigAlgID)
		{
			DerObjectIdentifier sigAlgOid = sigAlgID.Algorithm;
			Asn1Encodable sigAlgParams = sigAlgID.Parameters;

			if (!X509Utilities.IsAbsentParameters(sigAlgParams))
			{
                if (PkcsObjectIdentifiers.IdRsassaPss.Equals(sigAlgOid))
				{
					var rsassaPssParameters = RsassaPssParameters.GetInstance(sigAlgParams);

                    return GetDigestName(rsassaPssParameters.HashAlgorithm.Algorithm) + "withRSAandMGF1";
				}
                if (X9ObjectIdentifiers.ECDsaWithSha2.Equals(sigAlgOid))
				{
					AlgorithmIdentifier ecDsaParams = AlgorithmIdentifier.GetInstance(sigAlgParams);

					return GetDigestName(ecDsaParams.Algorithm) + "withECDSA";
				}
			}

			return SignerUtilities.GetEncodingName(sigAlgOid) ?? sigAlgOid.GetID();
		}
    }
}
