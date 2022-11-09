using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
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
    public static class PqcPrivateKeyFactory
    {
        /// <summary> Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.</summary>
        /// <param name="privateKeyInfoData"> the PrivateKeyInfo encoding</param>
        /// <returns> a suitable private key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(byte[] privateKeyInfoData)
        {
            return CreateKey(PrivateKeyInfo.GetInstance(Asn1Object.FromByteArray(privateKeyInfoData)));
        }

        /// <summary> Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a stream</summary>
        /// <param name="inStr"> the stream to read the PrivateKeyInfo encoding from</param>
        /// <returns> a suitable private key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(Stream inStr)
        {
            return CreateKey(PrivateKeyInfo.GetInstance(new Asn1InputStream(inStr).ReadObject()));
        }

        /// <summary> Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.</summary>
        /// <param name="keyInfo"> the PrivateKeyInfo object containing the key material</param>
        /// <returns> a suitable private key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(PrivateKeyInfo keyInfo)
        {
            AlgorithmIdentifier algId = keyInfo.PrivateKeyAlgorithm;
            DerObjectIdentifier algOID = algId.Algorithm;

            if (algOID.Equals(PkcsObjectIdentifiers.IdAlgHssLmsHashsig))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                DerBitString pubKey = keyInfo.PublicKeyData;

                if (Pack.BE_To_UInt32(keyEnc, 0) == 1)
                {
                    if (pubKey != null)
                    {
                        byte[] pubEnc = pubKey.GetOctets();

                        return LmsPrivateKeyParameters.GetInstance(Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length),
                            Arrays.CopyOfRange(pubEnc, 4, pubEnc.Length));
                    }

                    return LmsPrivateKeyParameters.GetInstance(Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
                }
            }
            if (algOID.On(BCObjectIdentifiers.pqc_kem_mceliece))
            {
                CmcePrivateKey cmceKey = CmcePrivateKey.GetInstance(keyInfo.ParsePrivateKey());
                CmceParameters spParams = PqcUtilities.McElieceParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                return new CmcePrivateKeyParameters(spParams, cmceKey.Delta, cmceKey.C, cmceKey.G, cmceKey.Alpha, cmceKey.S);
            }
            if (algOID.On(BCObjectIdentifiers.sphincsPlus))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                SphincsPlusParameters spParams = SphincsPlusParameters.GetParams(BigInteger.ValueOf(Pack.BE_To_UInt32(keyEnc, 0)).IntValue);

                return new SphincsPlusPrivateKeyParameters(spParams, Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
            }
            if (algOID.On(BCObjectIdentifiers.pqc_kem_saber))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                SaberParameters spParams = PqcUtilities.SaberParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                return new SaberPrivateKeyParameters(spParams, keyEnc);
            }
            if (algOID.On(BCObjectIdentifiers.picnic))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                PicnicParameters picnicParams = PqcUtilities.PicnicParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                return new PicnicPrivateKeyParameters(picnicParams, keyEnc);
            }
#pragma warning disable CS0618 // Type or member is obsolete
            if (algOID.On(BCObjectIdentifiers.pqc_kem_sike))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                SikeParameters sikeParams = PqcUtilities.SikeParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                return new SikePrivateKeyParameters(sikeParams, keyEnc);
            }
#pragma warning restore CS0618 // Type or member is obsolete
            if (algOID.On(BCObjectIdentifiers.pqc_kem_bike))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                byte[] h0 = Arrays.CopyOfRange(keyEnc, 0, bikeParams.RByte);
                byte[] h1 = Arrays.CopyOfRange(keyEnc, bikeParams.RByte, 2 * bikeParams.RByte);
                byte[] sigma = Arrays.CopyOfRange(keyEnc, 2 * bikeParams.RByte, keyEnc.Length);

                return new BikePrivateKeyParameters(bikeParams, h0, h1, sigma);
            }
            if (algOID.On(BCObjectIdentifiers.pqc_kem_hqc))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                return new HqcPrivateKeyParameters(hqcParams, keyEnc);
            }
            if (algOID.Equals(BCObjectIdentifiers.kyber512)
                || algOID.Equals(BCObjectIdentifiers.kyber512_aes)
                || algOID.Equals(BCObjectIdentifiers.kyber768)
                || algOID.Equals(BCObjectIdentifiers.kyber768_aes)
                || algOID.Equals(BCObjectIdentifiers.kyber1024)
                || algOID.Equals(BCObjectIdentifiers.kyber1024_aes))
            {
                Asn1Sequence keyEnc = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

                KyberParameters spParams = PqcUtilities.KyberParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                int version = DerInteger.GetInstance(keyEnc[0]).Value.IntValue;
                if (version != 0)
                {
                    throw new IOException("unknown private key version: " + version);
                }
 
                if (keyInfo.PublicKeyData != null)
                {
                    Asn1Sequence pubKey = Asn1Sequence.GetInstance(keyInfo.PublicKeyData.GetOctets());
                    return new KyberPrivateKeyParameters(spParams,
                        Asn1OctetString.GetInstance(keyEnc[1]).GetDerEncoded(), 
                        Asn1OctetString.GetInstance(keyEnc[2]).GetOctets(), 
                        Asn1OctetString.GetInstance(keyEnc[3]).GetOctets(),
                        Asn1OctetString.GetInstance(pubKey[0]).GetOctets(), // t
                        Asn1OctetString.GetInstance(pubKey[1]).GetOctets()); // rho
                }
                else
                {
                    return new KyberPrivateKeyParameters(spParams,
                        Asn1OctetString.GetInstance(keyEnc[1]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[2]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[3]).GetOctets(),
                        null,
                        null);
                }
            }
            if (algOID.Equals(BCObjectIdentifiers.dilithium2)
                || algOID.Equals(BCObjectIdentifiers.dilithium3)
                || algOID.Equals(BCObjectIdentifiers.dilithium5)
                || algOID.Equals(BCObjectIdentifiers.dilithium2_aes)
                || algOID.Equals(BCObjectIdentifiers.dilithium3_aes)
                || algOID.Equals(BCObjectIdentifiers.dilithium5_aes))
            {
                Asn1Sequence keyEnc = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

                DilithiumParameters spParams = PqcUtilities.DilithiumParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);

                int version = DerInteger.GetInstance(keyEnc[0]).Value.IntValue;
                if (version != 0)
                    throw new IOException("unknown private key version: " + version);

                if (keyInfo.PublicKeyData != null)
                {
                    Asn1Sequence pubKey = Asn1Sequence.GetInstance(keyInfo.PublicKeyData.GetOctets());
                    return new DilithiumPrivateKeyParameters(spParams,
                        DerBitString.GetInstance(keyEnc[1]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[2]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[3]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[4]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[5]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[6]).GetOctets(),
                        Asn1OctetString.GetInstance(pubKey[1]).GetOctets()); // encT1
                }
                else
                {
                    return new DilithiumPrivateKeyParameters(spParams,
                        DerBitString.GetInstance(keyEnc[1]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[2]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[3]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[4]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[5]).GetOctets(),
                        DerBitString.GetInstance(keyEnc[6]).GetOctets(),
                        null);
                }
            }
            if (algOID.Equals(BCObjectIdentifiers.falcon_512) || algOID.Equals(BCObjectIdentifiers.falcon_1024))
            {
                Asn1Sequence keyEnc = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());
                FalconParameters spParams = PqcUtilities.FalconParamsLookup(keyInfo.PrivateKeyAlgorithm.Algorithm);
                    
                DerBitString publicKeyData = keyInfo.PublicKeyData;
                int version = DerInteger.GetInstance(keyEnc[0]).Value.IntValue;
                if (version != 1)
                    throw new IOException("unknown private key version: " + version);

                if (keyInfo.PublicKeyData != null)
                {
                    //ASN1Sequence pubKey = ASN1Sequence.getInstance(keyInfo.getPublicKeyData().getOctets());
                    return new FalconPrivateKeyParameters(spParams,
                        Asn1OctetString.GetInstance(keyEnc[1]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[2]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[3]).GetOctets(),
                        publicKeyData.GetOctets()); // encT1
                }
                else
                {
                    return new FalconPrivateKeyParameters(spParams,
                        Asn1OctetString.GetInstance(keyEnc[1]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[2]).GetOctets(),
                        Asn1OctetString.GetInstance(keyEnc[3]).GetOctets(),
                        null);
                }
            }

            throw new Exception("algorithm identifier in private key not recognised");
        }
    }
}
