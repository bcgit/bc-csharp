using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509
{
    internal class X509SignatureUtilities
	{
        internal static bool AreEquivalentAlgorithms(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
        {
            if (!id1.Algorithm.Equals(id2.Algorithm))
                return false;

            // TODO Java has a property to control whether absent parameters can match NULL parameters
            {
                if (IsAbsentOrEmptyParameters(id1.Parameters) && IsAbsentOrEmptyParameters(id2.Parameters))
                    return true;
            }

			return Objects.Equals(id1.Parameters, id2.Parameters);
        }

		/**
		 * Return the digest algorithm using one of the standard JCA string
		 * representations rather than the algorithm identifier (if possible).
		 */
		private static string GetDigestAlgName(DerObjectIdentifier digestAlgOID)
		{
			if (PkcsObjectIdentifiers.MD5.Equals(digestAlgOID))
			{
				return "MD5";
			}
			else if (OiwObjectIdentifiers.IdSha1.Equals(digestAlgOID))
			{
				return "SHA1";
			}
			else if (NistObjectIdentifiers.IdSha224.Equals(digestAlgOID))
			{
				return "SHA224";
			}
			else if (NistObjectIdentifiers.IdSha256.Equals(digestAlgOID))
			{
				return "SHA256";
			}
			else if (NistObjectIdentifiers.IdSha384.Equals(digestAlgOID))
			{
				return "SHA384";
			}
			else if (NistObjectIdentifiers.IdSha512.Equals(digestAlgOID))
			{
				return "SHA512";
			}
			else if (TeleTrusTObjectIdentifiers.RipeMD128.Equals(digestAlgOID))
			{
				return "RIPEMD128";
			}
			else if (TeleTrusTObjectIdentifiers.RipeMD160.Equals(digestAlgOID))
			{
				return "RIPEMD160";
			}
			else if (TeleTrusTObjectIdentifiers.RipeMD256.Equals(digestAlgOID))
			{
				return "RIPEMD256";
			}
			else if (CryptoProObjectIdentifiers.GostR3411.Equals(digestAlgOID))
			{
				return "GOST3411";
			}
			else
			{
				return digestAlgOID.GetID();
            }
		}

        internal static string GetSignatureName(AlgorithmIdentifier sigAlgID)
		{
			DerObjectIdentifier sigAlgOid = sigAlgID.Algorithm;
			Asn1Encodable parameters = sigAlgID.Parameters;

			if (!IsAbsentOrEmptyParameters(parameters))
			{
                if (PkcsObjectIdentifiers.IdRsassaPss.Equals(sigAlgOid))
				{
					RsassaPssParameters rsaParams = RsassaPssParameters.GetInstance(parameters);

                    return GetDigestAlgName(rsaParams.HashAlgorithm.Algorithm) + "withRSAandMGF1";
				}
                if (X9ObjectIdentifiers.ECDsaWithSha2.Equals(sigAlgOid))
				{
					Asn1Sequence ecDsaParams = Asn1Sequence.GetInstance(parameters);

					return GetDigestAlgName((DerObjectIdentifier)ecDsaParams[0]) + "withECDSA";
				}
			}

			return SignerUtilities.GetEncodingName(sigAlgOid) ?? sigAlgOid.GetID();
		}

        private static bool IsAbsentOrEmptyParameters(Asn1Encodable parameters)
        {
            return parameters == null || DerNull.Instance.Equals(parameters);
        }
    }
}
