using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    
    /// <summary>
    /// A factory to produce Public Key Info Objects.
    /// </summary>
    public class SubjectPublicKeyInfoFactory
    {
        private SubjectPublicKeyInfoFactory()
        {
        }

        /// <summary>
        /// Create a Subject Public Key Info object for a given public key.
        /// </summary>
        /// <param name="publicKey">One of ElGammalPublicKeyParameters, DSAPublicKeyParameter, DHPublicKeyParameters, RsaKeyParameters or ECPublicKeyParameters</param>
        /// <returns>A subject public key info object.</returns>
        /// <exception cref="Exception">Throw exception if object provided is not one of the above.</exception>
        public static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(
            AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (publicKey.IsPrivate)
                throw new ArgumentException("Private key passed - public key expected.", "publicKey");
            
            if (publicKey is SphincsPlusPublicKeyParameters)
            {
                SphincsPlusPublicKeyParameters parameters = (SphincsPlusPublicKeyParameters)publicKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(
                    PqcUtilities.SphincsPlusOidLookup(parameters.Parameters));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
            }
            if (publicKey is CmcePublicKeyParameters)
            {
                CmcePublicKeyParameters key = (CmcePublicKeyParameters)publicKey;

                byte[] encoding = key.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.McElieceOidLookup(key.Parameters));

                // https://datatracker.ietf.org/doc/draft-uni-qsckeys/
                return new SubjectPublicKeyInfo(algorithmIdentifier, new CmcePublicKey(encoding));
            }
            if (publicKey is SaberPublicKeyParameters)
            {
                SaberPublicKeyParameters parameters = (SaberPublicKeyParameters)publicKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.SaberOidLookup(parameters.GetParameters()));

                // https://datatracker.ietf.org/doc/draft-uni-qsckeys/
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerSequence(new DerOctetString(encoding)));
            }
            if (publicKey is PicnicPublicKeyParameters)
            {
                PicnicPublicKeyParameters parameters = (PicnicPublicKeyParameters)publicKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.PicnicOidLookup(parameters.Parameters));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
            }
            if (publicKey is SIKEPublicKeyParameters)
            {
                SIKEPublicKeyParameters parameters = (SIKEPublicKeyParameters)publicKey;

                byte[] encoding = parameters.GetEncoded();

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.SikeOidLookup(parameters.GetParameters()));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
            }
            if (publicKey is FalconPublicKeyParameters)
            {
                FalconPublicKeyParameters parameters = (FalconPublicKeyParameters)publicKey;

                byte[] encoding = parameters.GetEncoded();
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.FalconOidLookup(parameters.Parameters));

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerSequence(new DerOctetString(encoding)));
            }
            if (publicKey is KyberPublicKeyParameters)
            {
                KyberPublicKeyParameters parameters = (KyberPublicKeyParameters)publicKey;

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.KyberOidLookup(parameters.Parameters));
                Asn1EncodableVector v = new Asn1EncodableVector();
                v.Add(new DerOctetString(parameters.T));
                v.Add(new DerOctetString(parameters.Rho));
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerSequence(v));
            }
            if (publicKey is DilithiumPublicKeyParameters)
            {
                DilithiumPublicKeyParameters parameters = (DilithiumPublicKeyParameters)publicKey;

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.DilithiumOidLookup(parameters.Parameters));
            
                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(Arrays.Concatenate(parameters.Rho, parameters.T1)));
            }
            if (publicKey is BikePublicKeyParameters)
            { 
                BikePublicKeyParameters parameters = (BikePublicKeyParameters)publicKey;

       
                byte[] encoding = parameters.GetEncoded();
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.BikeOidLookup(parameters.Parameters));

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
            }
            if (publicKey is HqcPublicKeyParameters)
            {
                HqcPublicKeyParameters parameters = (HqcPublicKeyParameters)publicKey;


                byte[] encoding = parameters.GetEncoded();
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PqcUtilities.HqcOidLookup(parameters.Parameters));

                return new SubjectPublicKeyInfo(algorithmIdentifier, new DerOctetString(encoding));
            }

            throw new ArgumentException("Class provided no convertible: " + Platform.GetTypeName(publicKey));
        }
        
        private static void ExtractBytes(
            byte[]		encKey,
            int			offset,
            BigInteger	bI)
        {
            byte[] val = bI.ToByteArray();
            int n = (bI.BitLength + 7) / 8;

            for (int i = 0; i < n; ++i)
            {
                encKey[offset + i] = val[val.Length - 1 - i];
            }
        }


        private static void ExtractBytes(byte[] encKey, int size, int offSet, BigInteger bI)
        {
            byte[] val = bI.ToByteArray();
            if (val.Length < size)
            {
                byte[] tmp = new byte[size];
                Array.Copy(val, 0, tmp, tmp.Length - val.Length, val.Length);
                val = tmp;
            }

            for (int i = 0; i != size; i++)
            {
                encKey[offSet + i] = val[val.Length - 1 - i];
            }
        }

    }
}