using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public static class PqcPrivateKeyInfoFactory
    {
        /// <summary> Create a PrivateKeyInfo representation of a private key.</summary>
        /// <param name="privateKey"> the key to be encoded into the info object.</param>
        /// <returns> the appropriate PrivateKeyInfo</returns>
        /// <exception cref="ArgumentException"> on an error encoding the key</exception>
        public static PrivateKeyInfo CreatePrivateKeyInfo(AsymmetricKeyParameter privateKey)
        {
            return CreatePrivateKeyInfo(privateKey, null);
        }

        /// <summary> Create a PrivateKeyInfo representation of a private key with attributes.</summary>
        /// <param name="privateKey"> the key to be encoded into the info object.</param>
        /// <param name="attributes"> the set of attributes to be included.</param>
        /// <returns> the appropriate PrivateKeyInfo</returns>
        /// <exception cref="ArgumentException"> on an error encoding the key</exception>
        public static PrivateKeyInfo CreatePrivateKeyInfo(AsymmetricKeyParameter privateKey, Asn1Set attributes)
        {
            if (privateKey is LmsPrivateKeyParameters lmsPrivateKeyParameters)
            {
                byte[] encoding = Composer.Compose().U32Str(1).Bytes(lmsPrivateKeyParameters).Build();
                byte[] pubEncoding = Composer.Compose().U32Str(1).Bytes(lmsPrivateKeyParameters.GetPublicKey()).Build();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is HssPrivateKeyParameters hssPrivateKeyParameters)
            {
                int L = hssPrivateKeyParameters.L;
                byte[] encoding = Composer.Compose().U32Str(L).Bytes(hssPrivateKeyParameters).Build();
                byte[] pubEncoding = Composer.Compose().U32Str(L).Bytes(hssPrivateKeyParameters.GetPublicKey().LmsPublicKey).Build();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is SphincsPlusPrivateKeyParameters sphincsPlusPrivateKeyParameters)
            {
                byte[] encoding = sphincsPlusPrivateKeyParameters.GetEncoded();
                byte[] pubEncoding = sphincsPlusPrivateKeyParameters.GetEncodedPublicKey();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.SphincsPlusOidLookup(sphincsPlusPrivateKeyParameters.Parameters));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is CmcePrivateKeyParameters cmcePrivateKeyParameters)
            {
                byte[] encoding = cmcePrivateKeyParameters.GetEncoded();
                AlgorithmIdentifier algorithmIdentifier =
                    new AlgorithmIdentifier(PqcUtilities.McElieceOidLookup(cmcePrivateKeyParameters.Parameters));

                CmcePublicKey CmcePub = new CmcePublicKey(cmcePrivateKeyParameters.ReconstructPublicKey());
                CmcePrivateKey CmcePriv = new CmcePrivateKey(0, cmcePrivateKeyParameters.Delta,
                    cmcePrivateKeyParameters.C, cmcePrivateKeyParameters.G, cmcePrivateKeyParameters.Alpha,
                    cmcePrivateKeyParameters.S, CmcePub);
                return new PrivateKeyInfo(algorithmIdentifier, CmcePriv, attributes);
            }
            if (privateKey is SaberPrivateKeyParameters saberPrivateKeyParameters)
            {
                byte[] encoding = saberPrivateKeyParameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.SaberOidLookup(saberPrivateKeyParameters.Parameters));

                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
            if (privateKey is PicnicPrivateKeyParameters picnicPrivateKeyParameters)
            {
                byte[] encoding = picnicPrivateKeyParameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.PicnicOidLookup(picnicPrivateKeyParameters.Parameters));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
#pragma warning disable CS0618 // Type or member is obsolete
            if (privateKey is SikePrivateKeyParameters sikePrivateKeyParameters)
            {
                byte[] encoding = sikePrivateKeyParameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.SikeOidLookup(sikePrivateKeyParameters.Parameters));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
#pragma warning restore CS0618 // Type or member is obsolete
            if (privateKey is FalconPrivateKeyParameters falconPrivateKeyParameters)
            {
                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(1));
                v.Add(new DerOctetString(falconPrivateKeyParameters.GetSpolyLittleF()));
                v.Add(new DerOctetString(falconPrivateKeyParameters.GetG()));
                v.Add(new DerOctetString(falconPrivateKeyParameters.GetSpolyBigF()));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.FalconOidLookup(falconPrivateKeyParameters.Parameters));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes,
                    falconPrivateKeyParameters.GetPublicKey());
            }
            if (privateKey is KyberPrivateKeyParameters kyberPrivateKeyParameters)
            {
                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(0));
                v.Add(new DerOctetString(kyberPrivateKeyParameters.S));
                v.Add(new DerOctetString(kyberPrivateKeyParameters.Hpk));
                v.Add(new DerOctetString(kyberPrivateKeyParameters.Nonce));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.KyberOidLookup(kyberPrivateKeyParameters.Parameters));

                Asn1EncodableVector vPub = new Asn1EncodableVector();
                vPub.Add(new DerOctetString(kyberPrivateKeyParameters.T));
                vPub.Add(new DerOctetString(kyberPrivateKeyParameters.Rho));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes,
                    new DerSequence(vPub).GetEncoded());
            }
            if (privateKey is DilithiumPrivateKeyParameters dilithiumPrivateKeyParameters)
            {
                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(0));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.Rho));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.K));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.Tr));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.S1));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.S2));
                v.Add(new DerBitString(dilithiumPrivateKeyParameters.T0));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.DilithiumOidLookup(dilithiumPrivateKeyParameters.Parameters));

                Asn1EncodableVector vPub = new Asn1EncodableVector();
                vPub.Add(new DerOctetString(dilithiumPrivateKeyParameters.Rho));
                vPub.Add(new DerOctetString(dilithiumPrivateKeyParameters.T1));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes,
                    new DerSequence(vPub).GetEncoded());
            }
            if (privateKey is BikePrivateKeyParameters bikePrivateKeyParameters)
            {
                byte[] encoding = bikePrivateKeyParameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.BikeOidLookup(bikePrivateKeyParameters.Parameters));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
            else if (privateKey is HqcPrivateKeyParameters hqcPrivateKeyParameters)
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.HqcOidLookup(hqcPrivateKeyParameters.Parameters));
                byte[] encoding = hqcPrivateKeyParameters.PrivateKey;
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }

            throw new ArgumentException("Class provided is not convertible: " + Platform.GetTypeName(privateKey));
        }
    }
}
