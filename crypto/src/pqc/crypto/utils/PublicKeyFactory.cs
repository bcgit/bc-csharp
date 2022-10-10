using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public class PublicKeyFactory
    {
        private static Dictionary<DerObjectIdentifier, SubjectPublicKeyInfoConverter> converters = new Dictionary<DerObjectIdentifier, SubjectPublicKeyInfoConverter>();


        static PublicKeyFactory()
        {
            converters[BCObjectIdentifiers.sphincsPlus] = new SphincsPlusConverter();
            converters[BCObjectIdentifiers.sphincsPlus_shake_256] = new SphincsPlusConverter();
            converters[BCObjectIdentifiers.sphincsPlus_sha_256] = new SphincsPlusConverter();
            converters[BCObjectIdentifiers.sphincsPlus_sha_512] = new SphincsPlusConverter();
            
            converters[BCObjectIdentifiers.mceliece348864_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece348864f_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece460896_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece460896f_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece6688128_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece6688128f_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece6960119_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece6960119f_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece8192128_r3] = new CmceConverter();
            converters[BCObjectIdentifiers.mceliece8192128f_r3] = new CmceConverter();
           
            converters[BCObjectIdentifiers.lightsaberkem128r3] = new SaberConverter();
            converters[BCObjectIdentifiers.saberkem128r3] = new SaberConverter();
            converters[BCObjectIdentifiers.firesaberkem128r3] = new SaberConverter();
            converters[BCObjectIdentifiers.lightsaberkem192r3] = new SaberConverter();
            converters[BCObjectIdentifiers.saberkem192r3] = new SaberConverter();
            converters[BCObjectIdentifiers.firesaberkem192r3] = new SaberConverter();
            converters[BCObjectIdentifiers.lightsaberkem256r3] = new SaberConverter();
            converters[BCObjectIdentifiers.saberkem256r3] = new SaberConverter();
            converters[BCObjectIdentifiers.firesaberkem256r3] = new SaberConverter();
            
            converters[BCObjectIdentifiers.picnic] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl1fs] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl1ur] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl3fs] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl3ur] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl5fs] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl5ur] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnic3l1] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnic3l3] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnic3l5] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl1full] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl3full] = new PicnicConverter();
            converters[BCObjectIdentifiers.picnicl5full] = new PicnicConverter();
            
            converters[BCObjectIdentifiers.sikep434] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep503] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep610] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep751] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep434_compressed] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep503_compressed] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep610_compressed] = new SikeConverter();
            converters[BCObjectIdentifiers.sikep751_compressed] = new SikeConverter();
            
            converters[BCObjectIdentifiers.dilithium2] = new DilithiumConverter();
            converters[BCObjectIdentifiers.dilithium3] = new DilithiumConverter();
            converters[BCObjectIdentifiers.dilithium5] = new DilithiumConverter();
            converters[BCObjectIdentifiers.dilithium2_aes] = new DilithiumConverter();
            converters[BCObjectIdentifiers.dilithium3_aes] = new DilithiumConverter();
            converters[BCObjectIdentifiers.dilithium5_aes] = new DilithiumConverter();
            
            converters[BCObjectIdentifiers.falcon_512] = new FalconConverter();
            converters[BCObjectIdentifiers.falcon_1024] = new FalconConverter();
            
            converters[BCObjectIdentifiers.kyber512] = new KyberConverter();
            converters[BCObjectIdentifiers.kyber512_aes] = new KyberConverter();
            converters[BCObjectIdentifiers.kyber768] = new KyberConverter();
            converters[BCObjectIdentifiers.kyber768_aes] = new KyberConverter();
            converters[BCObjectIdentifiers.kyber1024] = new KyberConverter();
            converters[BCObjectIdentifiers.kyber1024_aes] = new KyberConverter();
        }
        
        /// <summary> Create a public key from a SubjectPublicKeyInfo encoding</summary>
        /// <param name="keyInfoData"> the SubjectPublicKeyInfo encoding</param>
        /// <returns> the appropriate key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(byte[] keyInfoData)
        {
            return CreateKey(SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(keyInfoData)));
        }

        /// <summary> Create a public key from a SubjectPublicKeyInfo encoding read from a stream</summary>
        /// <param name="inStr"> the stream to read the SubjectPublicKeyInfo encoding from</param>
        /// <returns>the appropriate key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(Stream inStr)
        {
            return CreateKey(SubjectPublicKeyInfo.GetInstance(new Asn1InputStream(inStr).ReadObject()));
        }
        
        /// <summary> Create a public key from the passed in SubjectPublicKeyInfo</summary>
        /// <param name="keyInfo"> the SubjectPublicKeyInfo containing the key data</param>
        /// <returns> the appropriate key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo keyInfo)
        {
            return CreateKey(keyInfo, null);
        }
        
        /// <summary> Create a public key from the passed in SubjectPublicKeyInfo</summary>
        /// <param name="keyInfo"> the SubjectPublicKeyInfo containing the key data</param>
        /// <param name="defaultParams"> default parameters that might be needed.</param>
        /// <returns> the appropriate key parameter</returns>
        /// <exception cref="IOException"> on an error decoding the key</exception>
        public static AsymmetricKeyParameter CreateKey(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            AlgorithmIdentifier algId = keyInfo.AlgorithmID;
            SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter)converters[algId.Algorithm];

            if (converter != null)
            {
                return converter.GetPublicKeyParameters(keyInfo, defaultParams);
            }
            else
            {
                throw new IOException("algorithm identifier in public key not recognised: " + algId.Algorithm);
            }
        }
        private abstract class SubjectPublicKeyInfoConverter
        {
            internal abstract AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams);
        }
        
        private class SphincsPlusConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
            byte[] keyEnc = DerOctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

            SphincsPlusParameters spParams = SphincsPlusParameters.GetParams((uint)BigInteger.ValueOf(Pack.BE_To_UInt32(keyEnc, 0)).IntValue);

            return new SphincsPlusPublicKeyParameters(spParams, Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
            }
        }
        
        private class CmceConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = CmcePublicKey.GetInstance(keyInfo.ParsePublicKey()).T;

                CmceParameters spParams = PqcUtilities.McElieceParamsLookup(keyInfo.AlgorithmID.Algorithm);

                return new CmcePublicKeyParameters(spParams, keyEnc);
            }
        }

        private class SaberConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = DerOctetString.GetInstance(
                    DerSequence.GetInstance(keyInfo.ParsePublicKey())[0]).GetOctets();

                SABERParameters saberParams = PqcUtilities.SaberParamsLookup(keyInfo.AlgorithmID.Algorithm);

                    return new SABERPublicKeyParameters(saberParams, keyEnc);
            }
        }
        
        private class PicnicConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = DerOctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                PicnicParameters picnicParams = PqcUtilities.PicnicParamsLookup(keyInfo.AlgorithmID.Algorithm);

                return new PicnicPublicKeyParameters(picnicParams, keyEnc);
            }
        }
        private class SikeConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = DerOctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                SIKEParameters sikeParams = PqcUtilities.SikeParamsLookup(keyInfo.AlgorithmID.Algorithm);

                return new SIKEPublicKeyParameters(sikeParams, keyEnc);
            }
        }
        private class DilithiumConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                DilithiumParameters dilithiumParams = PqcUtilities.DilithiumParamsLookup(keyInfo.AlgorithmID.Algorithm);

                Asn1Object obj = keyInfo.ParsePublicKey();
                if (obj is Asn1Sequence)
                {
                    Asn1Sequence keySeq = Asn1Sequence.GetInstance(obj);

                    return new DilithiumPublicKeyParameters(dilithiumParams,
                        Asn1OctetString.GetInstance(keySeq[0]).GetOctets(),
                        Asn1OctetString.GetInstance(keySeq[1]).GetOctets());
                }
                else
                {
                    byte[] encKey = Asn1OctetString.GetInstance(obj).GetOctets();

                    return new DilithiumPublicKeyParameters(dilithiumParams, encKey);
                }
            }
        }

        private class KyberConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                KyberParameters kyberParameters = PqcUtilities.KyberParamsLookup(keyInfo.AlgorithmID.Algorithm);

                Asn1Object obj = keyInfo.ParsePublicKey();
                if (obj is Asn1Sequence)
                {
                    Asn1Sequence keySeq = Asn1Sequence.GetInstance(obj);

                    return new KyberPublicKeyParameters(kyberParameters,
                        Asn1OctetString.GetInstance(keySeq[0]).GetOctets(),
                        Asn1OctetString.GetInstance(keySeq[1]).GetOctets());
                }
                else
                {
                    byte[] encKey = Asn1OctetString.GetInstance(obj).GetOctets();

                    return new KyberPublicKeyParameters(kyberParameters, encKey);
                }
            }
        }

        private class FalconConverter 
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                FalconParameters falconParams = PqcUtilities.FalconParamsLookup(keyInfo.AlgorithmID.Algorithm);

                Asn1Object obj = keyInfo.ParsePublicKey();
                if (obj is Asn1Sequence)
                {
                    byte[] keyEnc = Asn1OctetString.GetInstance(Asn1Sequence.GetInstance(obj)[0]).GetOctets();

                    return new FalconPublicKeyParameters(falconParams, keyEnc);
                }
                else
                {
                    // header byte + h
                    byte[] keyEnc = Asn1OctetString.GetInstance(obj).GetOctets();

                    if (keyEnc[0] != (byte)(0x00 + falconParams.LogN))
                    {
                        throw new ArgumentException("byte[] enc of Falcon h value not tagged correctly");
                    }
                    return new FalconPublicKeyParameters(falconParams, Arrays.CopyOfRange(keyEnc, 1, keyEnc.Length));
                }
            }
        }
    }
}