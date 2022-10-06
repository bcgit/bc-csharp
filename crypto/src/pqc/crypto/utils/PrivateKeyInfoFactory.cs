using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public class PrivateKeyInfoFactory
    {
        private PrivateKeyInfoFactory()
        {

        }

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
            if (privateKey is LMSPrivateKeyParameters)
            {
                LMSPrivateKeyParameters parameters = (LMSPrivateKeyParameters)privateKey;

                byte[] encoding = Composer.Compose().U32Str(1).Bytes(parameters).Build();
                byte[] pubEncoding = Composer.Compose().U32Str(1).Bytes(parameters.GetPublicKey()).Build();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is HSSPrivateKeyParameters)
            {
                HSSPrivateKeyParameters parameters = (HSSPrivateKeyParameters)privateKey;

                byte[] encoding = Composer.Compose().U32Str(parameters.L).Bytes(parameters).Build();
                byte[] pubEncoding = Composer.Compose().U32Str(parameters.L).Bytes(parameters.GetPublicKey().LmsPublicKey).Build();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdAlgHssLmsHashsig);
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is SPHINCSPlusPrivateKeyParameters)
            {
                SPHINCSPlusPrivateKeyParameters parameters = (SPHINCSPlusPrivateKeyParameters)privateKey;

                byte[] encoding = parameters.GetEncoded();
                byte[] pubEncoding = parameters.GetEncodedPublicKey();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.SphincsPlusOidLookup(parameters.GetParameters()));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes, pubEncoding);
            }
            if (privateKey is CmcePrivateKeyParameters)
            {
                CmcePrivateKeyParameters parameters = (CmcePrivateKeyParameters) privateKey;

                byte[] encoding = parameters.GetEncoded();
                AlgorithmIdentifier algorithmIdentifier =
                    new AlgorithmIdentifier(PqcUtilities.McElieceOidLookup(parameters.Parameters));

                CmcePublicKey CmcePub = new CmcePublicKey(parameters.ReconstructPublicKey());
                CmcePrivateKey CmcePriv = new CmcePrivateKey(0, parameters.Delta, parameters.C, parameters.G,
                    parameters.Alpha, parameters.S, CmcePub);
                return new PrivateKeyInfo(algorithmIdentifier, CmcePriv, attributes);
            }
            if (privateKey is SABERPrivateKeyParameters)
            {
                SABERPrivateKeyParameters parameters = (SABERPrivateKeyParameters)privateKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.SaberOidLookup(parameters.GetParameters()));

                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
            if (privateKey is PicnicPrivateKeyParameters)
            {
                PicnicPrivateKeyParameters parameters = (PicnicPrivateKeyParameters)privateKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.PicnicOidLookup(parameters.Parameters));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
            if (privateKey is SIKEPrivateKeyParameters)
            {
                SIKEPrivateKeyParameters parameters = (SIKEPrivateKeyParameters)privateKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.SikeOidLookup(parameters.GetParameters()));
                return new PrivateKeyInfo(algorithmIdentifier, new DerOctetString(encoding), attributes);
            }
            if (privateKey is FalconPrivateKeyParameters)
            {
                FalconPrivateKeyParameters parameters = (FalconPrivateKeyParameters)privateKey;

                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(1));
                v.Add(new DerOctetString(parameters.GetSpolyf()));
                v.Add(new DerOctetString(parameters.GetG()));
                v.Add(new DerOctetString(parameters.GetSpolyF()));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.FalconOidLookup(parameters.Parameters));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes, parameters.GetPublicKey());
            }
            if (privateKey is KyberPrivateKeyParameters)
            {
                KyberPrivateKeyParameters parameters = (KyberPrivateKeyParameters)privateKey;
            
                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(0));
                v.Add(new DerOctetString(parameters.S));
                v.Add(new DerOctetString(parameters.Hpk));
                v.Add(new DerOctetString(parameters.Nonce));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.KyberOidLookup(parameters.Parameters));

                Asn1EncodableVector vPub = new Asn1EncodableVector();
                vPub.Add(new DerOctetString(parameters.T));
                vPub.Add(new DerOctetString(parameters.Rho));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes, new DerSequence(vPub).GetEncoded());
            }
            if (privateKey is DilithiumPrivateKeyParameters)
            {
                DilithiumPrivateKeyParameters parameters = (DilithiumPrivateKeyParameters)privateKey;

                Asn1EncodableVector v = new Asn1EncodableVector();

                v.Add(new DerInteger(0));
                v.Add(new DerBitString(parameters.Rho));
                v.Add(new DerBitString(parameters.K));
                v.Add(new DerBitString(parameters.Tr));
                v.Add(new DerBitString(parameters.S1));
                v.Add(new DerBitString(parameters.S2));
                v.Add(new DerBitString(parameters.T0));

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.DilithiumOidLookup(parameters.Parameters));

                Asn1EncodableVector vPub = new Asn1EncodableVector();
                vPub.Add(new DerOctetString(parameters.Rho));
                vPub.Add(new DerOctetString(parameters.T1));

                return new PrivateKeyInfo(algorithmIdentifier, new DerSequence(v), attributes, new DerSequence(vPub).GetEncoded());
            }

            throw new ArgumentException("Class provided is not convertible: " + Platform.GetTypeName(privateKey));
        }
    }
}