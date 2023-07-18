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
using Org.BouncyCastle.Pqc.Crypto.Frodo;
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
            AlgorithmIdentifier algID = keyInfo.PrivateKeyAlgorithm;
            DerObjectIdentifier algOid = algID.Algorithm;

            if (algOid.Equals(PkcsObjectIdentifiers.IdAlgHssLmsHashsig))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                DerBitString pubKey = keyInfo.PublicKey;

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
            if (algOid.On(BCObjectIdentifiers.pqc_kem_mceliece))
            {
                CmcePrivateKey cmceKey = CmcePrivateKey.GetInstance(keyInfo.ParsePrivateKey());
                CmceParameters spParams = PqcUtilities.McElieceParamsLookup(algOid);

                return new CmcePrivateKeyParameters(spParams, cmceKey.Delta, cmceKey.C, cmceKey.G, cmceKey.Alpha, cmceKey.S);
            }
            if (algOid.On(BCObjectIdentifiers.pqc_kem_frodo))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                FrodoParameters spParams = PqcUtilities.FrodoParamsLookup(algOid);

                return new FrodoPrivateKeyParameters(spParams, keyEnc);
            }
            if (algOid.On(BCObjectIdentifiers.sphincsPlus))
            {
                SphincsPlusPrivateKey spKey = SphincsPlusPrivateKey.GetInstance(keyInfo.ParsePrivateKey());
                SphincsPlusParameters spParams = PqcUtilities.SphincsPlusParamsLookup(algOid);
                SphincsPlusPublicKey publicKey = spKey.PublicKey;

                return new SphincsPlusPrivateKeyParameters(spParams, spKey.GetSkseed(), spKey.GetSkprf(),
                    publicKey.GetPkseed(), publicKey.GetPkroot());
            }
            if (algOid.On(BCObjectIdentifiers.pqc_kem_saber))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                SaberParameters spParams = PqcUtilities.SaberParamsLookup(algOid);

                return new SaberPrivateKeyParameters(spParams, keyEnc);
            }
            if (algOid.On(BCObjectIdentifiers.picnic))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                PicnicParameters picnicParams = PqcUtilities.PicnicParamsLookup(algOid);

                return new PicnicPrivateKeyParameters(picnicParams, keyEnc);
            }
#pragma warning disable CS0618 // Type or member is obsolete
            if (algOid.On(BCObjectIdentifiers.pqc_kem_sike))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                SikeParameters sikeParams = PqcUtilities.SikeParamsLookup(algOid);

                return new SikePrivateKeyParameters(sikeParams, keyEnc);
            }
#pragma warning restore CS0618 // Type or member is obsolete
            if (algOid.On(BCObjectIdentifiers.pqc_kem_bike))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(algOid);

                byte[] h0 = Arrays.CopyOfRange(keyEnc, 0, bikeParams.RByte);
                byte[] h1 = Arrays.CopyOfRange(keyEnc, bikeParams.RByte, 2 * bikeParams.RByte);
                byte[] sigma = Arrays.CopyOfRange(keyEnc, 2 * bikeParams.RByte, keyEnc.Length);

                return new BikePrivateKeyParameters(bikeParams, h0, h1, sigma);
            }
            if (algOid.On(BCObjectIdentifiers.pqc_kem_hqc))
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
                HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(algOid);

                return new HqcPrivateKeyParameters(hqcParams, keyEnc);
            }
            if (algOid.On(BCObjectIdentifiers.pqc_kem_kyber))
            {
                KyberPrivateKey kyberKey = KyberPrivateKey.GetInstance(keyInfo.ParsePrivateKey());
                KyberParameters kyberParams = PqcUtilities.KyberParamsLookup(algOid);

#pragma warning disable CS0618 // Type or member is obsolete
                KyberPublicKey pubKey = kyberKey.PublicKey;
#pragma warning restore CS0618 // Type or member is obsolete
                if (pubKey != null)
                {
                    return new KyberPrivateKeyParameters(kyberParams, kyberKey.GetS(), kyberKey.GetHpk(),
                        kyberKey.GetNonce(), pubKey.T, pubKey.Rho);
                }
                return new KyberPrivateKeyParameters(kyberParams, kyberKey.GetS(), kyberKey.GetHpk(),
                    kyberKey.GetNonce(), null, null);
            }
            if (algOid.Equals(BCObjectIdentifiers.dilithium2) ||
                algOid.Equals(BCObjectIdentifiers.dilithium3) ||
                algOid.Equals(BCObjectIdentifiers.dilithium5) ||
                algOid.Equals(BCObjectIdentifiers.dilithium2_aes) ||
                algOid.Equals(BCObjectIdentifiers.dilithium3_aes) ||
                algOid.Equals(BCObjectIdentifiers.dilithium5_aes))
            {
                Asn1Sequence keyEnc = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());

                DilithiumParameters spParams = PqcUtilities.DilithiumParamsLookup(algOid);

                int version = DerInteger.GetInstance(keyEnc[0]).IntValueExact;
                if (version != 0)
                    throw new IOException("unknown private key version: " + version);

                byte[] t1 = null;

                DerBitString publicKeyData = keyInfo.PublicKey;
                if (publicKeyData != null)
                {
                    var pubParams = PqcPublicKeyFactory.DilithiumConverter.GetPublicKeyParameters(spParams,
                        publicKeyData);

                    t1 = pubParams.GetT1();
                }

                return new DilithiumPrivateKeyParameters(spParams,
                    DerBitString.GetInstance(keyEnc[1]).GetOctets(),
                    DerBitString.GetInstance(keyEnc[2]).GetOctets(),
                    DerBitString.GetInstance(keyEnc[3]).GetOctets(),
                    DerBitString.GetInstance(keyEnc[4]).GetOctets(),
                    DerBitString.GetInstance(keyEnc[5]).GetOctets(),
                    DerBitString.GetInstance(keyEnc[6]).GetOctets(),
                    t1); // encT1
            }
            if (algOid.Equals(BCObjectIdentifiers.falcon_512) ||
                algOid.Equals(BCObjectIdentifiers.falcon_1024))
            {
                Asn1Sequence keyEnc = Asn1Sequence.GetInstance(keyInfo.ParsePrivateKey());
                FalconParameters spParams = PqcUtilities.FalconParamsLookup(algOid);

                int version = DerInteger.GetInstance(keyEnc[0]).IntValueExact;
                if (version != 1)
                    throw new IOException("unknown private key version: " + version);

                return new FalconPrivateKeyParameters(spParams,
                    Asn1OctetString.GetInstance(keyEnc[1]).GetOctets(),
                    Asn1OctetString.GetInstance(keyEnc[2]).GetOctets(),
                    Asn1OctetString.GetInstance(keyEnc[3]).GetOctets(),
                    keyInfo.PublicKey?.GetOctets()); // encT1
            }

            throw new Exception("algorithm identifier in private key not recognised");
        }
    }
}
