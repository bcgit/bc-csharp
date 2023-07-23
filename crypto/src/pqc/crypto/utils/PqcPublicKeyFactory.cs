using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
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
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public static class PqcPublicKeyFactory
    {
        private static Dictionary<DerObjectIdentifier, SubjectPublicKeyInfoConverter> Converters =
            new Dictionary<DerObjectIdentifier, SubjectPublicKeyInfoConverter>();

        static PqcPublicKeyFactory()
        {
            Converters[PkcsObjectIdentifiers.IdAlgHssLmsHashsig] = new LmsConverter();
            
            Converters[BCObjectIdentifiers.mceliece348864_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece348864f_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece460896_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece460896f_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece6688128_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece6688128f_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece6960119_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece6960119f_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece8192128_r3] = new CmceConverter();
            Converters[BCObjectIdentifiers.mceliece8192128f_r3] = new CmceConverter();

            Converters[BCObjectIdentifiers.frodokem640aes] = new FrodoConverter();
            Converters[BCObjectIdentifiers.frodokem640shake] = new FrodoConverter();
            Converters[BCObjectIdentifiers.frodokem976aes] = new FrodoConverter();
            Converters[BCObjectIdentifiers.frodokem976shake] = new FrodoConverter();
            Converters[BCObjectIdentifiers.frodokem1344aes] = new FrodoConverter();
            Converters[BCObjectIdentifiers.frodokem1344shake] = new FrodoConverter();

            Converters[BCObjectIdentifiers.lightsaberkem128r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.saberkem128r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.firesaberkem128r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.lightsaberkem192r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.saberkem192r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.firesaberkem192r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.lightsaberkem256r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.saberkem256r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.firesaberkem256r3] = new SaberConverter();
            Converters[BCObjectIdentifiers.ulightsaberkemr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.usaberkemr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.ufiresaberkemr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.lightsaberkem90sr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.saberkem90sr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.firesaberkem90sr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.ulightsaberkem90sr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.usaberkem90sr3] = new SaberConverter();
            Converters[BCObjectIdentifiers.ufiresaberkem90sr3] = new SaberConverter();
            
            Converters[BCObjectIdentifiers.picnic] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl1fs] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl1ur] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl3fs] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl3ur] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl5fs] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl5ur] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnic3l1] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnic3l3] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnic3l5] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl1full] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl3full] = new PicnicConverter();
            Converters[BCObjectIdentifiers.picnicl5full] = new PicnicConverter();

#pragma warning disable CS0618 // Type or member is obsolete
            Converters[BCObjectIdentifiers.sikep434] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep503] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep610] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep751] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep434_compressed] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep503_compressed] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep610_compressed] = new SikeConverter();
            Converters[BCObjectIdentifiers.sikep751_compressed] = new SikeConverter();
#pragma warning restore CS0618 // Type or member is obsolete

            Converters[BCObjectIdentifiers.dilithium2] = new DilithiumConverter();
            Converters[BCObjectIdentifiers.dilithium3] = new DilithiumConverter();
            Converters[BCObjectIdentifiers.dilithium5] = new DilithiumConverter();
            Converters[BCObjectIdentifiers.dilithium2_aes] = new DilithiumConverter();
            Converters[BCObjectIdentifiers.dilithium3_aes] = new DilithiumConverter();
            Converters[BCObjectIdentifiers.dilithium5_aes] = new DilithiumConverter();
            
            Converters[BCObjectIdentifiers.falcon_512] = new FalconConverter();
            Converters[BCObjectIdentifiers.falcon_1024] = new FalconConverter();
            
            Converters[BCObjectIdentifiers.kyber512] = new KyberConverter();
            Converters[BCObjectIdentifiers.kyber512_aes] = new KyberConverter();
            Converters[BCObjectIdentifiers.kyber768] = new KyberConverter();
            Converters[BCObjectIdentifiers.kyber768_aes] = new KyberConverter();
            Converters[BCObjectIdentifiers.kyber1024] = new KyberConverter();
            Converters[BCObjectIdentifiers.kyber1024_aes] = new KyberConverter();

            Converters[BCObjectIdentifiers.bike128] = new BikeConverter();
            Converters[BCObjectIdentifiers.bike192] = new BikeConverter();
            Converters[BCObjectIdentifiers.bike256] = new BikeConverter();

            Converters[BCObjectIdentifiers.hqc128] = new HqcConverter();
            Converters[BCObjectIdentifiers.hqc192] = new HqcConverter();
            Converters[BCObjectIdentifiers.hqc256] = new HqcConverter();


            Converters[BCObjectIdentifiers.sphincsPlus] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256f_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256s_r3] = new SphincsPlusConverter();
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256f_r3] = new SphincsPlusConverter();
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
            var oid = keyInfo.Algorithm.Algorithm;

            SubjectPublicKeyInfoConverter converter = CollectionUtilities.GetValueOrNull(Converters, oid)
                ?? throw new IOException("algorithm identifier in public key not recognised: " + oid);

            return converter.GetPublicKeyParameters(keyInfo, defaultParams);
        }

        internal abstract class SubjectPublicKeyInfoConverter
        {
            internal abstract AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams);
        }

        private class LmsConverter
        :   SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                if (Pack.BE_To_UInt32(keyEnc, 0) == 1U)
                {
                    return LmsPublicKeyParameters.GetInstance(Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
                }
                else
                {
                    // public key with extra tree height
                    if (keyEnc.Length == 64)
                    {
                        keyEnc = Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length);
                    }
                    return HssPublicKeyParameters.GetInstance(keyEnc);
                }
            }
        }

        private class SphincsPlusConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                SphincsPlusParameters spParams = PqcUtilities.SphincsPlusParamsLookup(keyInfo.Algorithm.Algorithm);

                return new SphincsPlusPublicKeyParameters(spParams, Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
            }
        }
        
        private class CmceConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = CmcePublicKey.GetInstance(keyInfo.ParsePublicKey()).T;

                CmceParameters spParams = PqcUtilities.McElieceParamsLookup(keyInfo.Algorithm.Algorithm);

                return new CmcePublicKeyParameters(spParams, keyEnc);
            }
        }

        private class FrodoConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                FrodoParameters fParams = PqcUtilities.FrodoParamsLookup(keyInfo.Algorithm.Algorithm);

                return new FrodoPublicKeyParameters(fParams, keyEnc);
            }
        }

        private class SaberConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(
                    Asn1Sequence.GetInstance(keyInfo.ParsePublicKey())[0]).GetOctets();

                SaberParameters saberParams = PqcUtilities.SaberParamsLookup(keyInfo.Algorithm.Algorithm);

                return new SaberPublicKeyParameters(saberParams, keyEnc);
            }
        }
        
        private class PicnicConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                PicnicParameters picnicParams = PqcUtilities.PicnicParamsLookup(keyInfo.Algorithm.Algorithm);

                return new PicnicPublicKeyParameters(picnicParams, keyEnc);
            }
        }

        [Obsolete("Will be removed")]
        private class SikeConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                SikeParameters sikeParams = PqcUtilities.SikeParamsLookup(keyInfo.Algorithm.Algorithm);

                return new SikePublicKeyParameters(sikeParams, keyEnc);
            }
        }

        internal class DilithiumConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo,
                object defaultParams)
            {
                var dilithiumParameters = PqcUtilities.DilithiumParamsLookup(keyInfo.Algorithm.Algorithm);

                return GetPublicKeyParameters(dilithiumParameters, keyInfo.PublicKey);
            }

            internal static DilithiumPublicKeyParameters GetPublicKeyParameters(DilithiumParameters dilithiumParameters,
                DerBitString publicKeyData)
            {
                try
                {
                    Asn1Object obj = Asn1Object.FromByteArray(publicKeyData.GetOctets());
                    if (obj is Asn1Sequence keySeq)
                    {
                        return new DilithiumPublicKeyParameters(dilithiumParameters,
                            Asn1OctetString.GetInstance(keySeq[0]).GetOctets(),
                            Asn1OctetString.GetInstance(keySeq[1]).GetOctets());
                    }
                    else
                    {
                        byte[] encKey = Asn1OctetString.GetInstance(obj).GetOctets();

                        return new DilithiumPublicKeyParameters(dilithiumParameters, encKey);
                    }
                }
                catch (Exception)
                {
                    // we're a raw encoding
                    return new DilithiumPublicKeyParameters(dilithiumParameters, publicKeyData.GetOctets());
                }
            }
        }

        private class KyberConverter
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo,
                object defaultParams)
            {
                KyberParameters kyberParameters = PqcUtilities.KyberParamsLookup(keyInfo.Algorithm.Algorithm);

                try
                {
                    Asn1Object obj = keyInfo.ParsePublicKey();
#pragma warning disable CS0618 // Type or member is obsolete
                    KyberPublicKey kyberKey = KyberPublicKey.GetInstance(obj);
#pragma warning restore CS0618 // Type or member is obsolete

                    return new KyberPublicKeyParameters(kyberParameters, kyberKey.T, kyberKey.Rho);
                }
                catch (Exception)
                {
                    // we're a raw encoding
                    return new KyberPublicKeyParameters(kyberParameters, keyInfo.PublicKey.GetOctets());
                }
            }
        }

        private class FalconConverter 
            : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                FalconParameters falconParams = PqcUtilities.FalconParamsLookup(keyInfo.Algorithm.Algorithm);

                try
                {
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
                catch (Exception)
                {
                    // raw encoding
                    byte[] keyEnc = keyInfo.PublicKey.GetOctets();

                    if (keyEnc[0] != (byte)(0x00 + falconParams.LogN))
                    {
                        throw new ArgumentException("byte[] enc of Falcon h value not tagged correctly");
                    }
                    return new FalconPublicKeyParameters(falconParams, Arrays.CopyOfRange(keyEnc, 1, keyEnc.Length));
                }
            }
        }

        private class BikeConverter: SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                try
                {
                    byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                    BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(keyInfo.Algorithm.Algorithm);

                    return new BikePublicKeyParameters(bikeParams, keyEnc);
                }
                catch (Exception e)
                {
                    byte[] keyEnc = keyInfo.PublicKeyData.GetOctets();

                    BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(keyInfo.Algorithm.Algorithm);

                    return new BikePublicKeyParameters(bikeParams, keyEnc);
                }
            }
        }

        private class HqcConverter : SubjectPublicKeyInfoConverter
        {
            internal override AsymmetricKeyParameter GetPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
            {
                try
                {
                    byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                    HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(keyInfo.Algorithm.Algorithm);

                    return new HqcPublicKeyParameters(hqcParams, keyEnc);
                }
                catch (Exception e)
                {
                    // raw encoding
                    byte[] keyEnc = keyInfo.PublicKeyData.GetOctets();

                    HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(keyInfo.Algorithm.Algorithm);

                    return new HqcPublicKeyParameters(hqcParams, keyEnc);
                }
            }
        }
    }
}
