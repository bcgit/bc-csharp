using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pqc.Asn1;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Pqc.Crypto.MLKem;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    public static class PqcPublicKeyFactory
    {
        private delegate AsymmetricKeyParameter Converter(SubjectPublicKeyInfo keyInfo, object defaultParams);

        private static Dictionary<DerObjectIdentifier, Converter> Converters =
            new Dictionary<DerObjectIdentifier, Converter>();

        static PqcPublicKeyFactory()
        {
            Converters[PkcsObjectIdentifiers.IdAlgHssLmsHashsig] = LmsConverter;

            Converters[BCObjectIdentifiers.mceliece348864_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece348864f_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece460896_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece460896f_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece6688128_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece6688128f_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece6960119_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece6960119f_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece8192128_r3] = CmceConverter;
            Converters[BCObjectIdentifiers.mceliece8192128f_r3] = CmceConverter;

            Converters[BCObjectIdentifiers.frodokem640aes] = FrodoConverter;
            Converters[BCObjectIdentifiers.frodokem640shake] = FrodoConverter;
            Converters[BCObjectIdentifiers.frodokem976aes] = FrodoConverter;
            Converters[BCObjectIdentifiers.frodokem976shake] = FrodoConverter;
            Converters[BCObjectIdentifiers.frodokem1344aes] = FrodoConverter;
            Converters[BCObjectIdentifiers.frodokem1344shake] = FrodoConverter;

            Converters[BCObjectIdentifiers.lightsaberkem128r3] = SaberConverter;
            Converters[BCObjectIdentifiers.saberkem128r3] = SaberConverter;
            Converters[BCObjectIdentifiers.firesaberkem128r3] = SaberConverter;
            Converters[BCObjectIdentifiers.lightsaberkem192r3] = SaberConverter;
            Converters[BCObjectIdentifiers.saberkem192r3] = SaberConverter;
            Converters[BCObjectIdentifiers.firesaberkem192r3] = SaberConverter;
            Converters[BCObjectIdentifiers.lightsaberkem256r3] = SaberConverter;
            Converters[BCObjectIdentifiers.saberkem256r3] = SaberConverter;
            Converters[BCObjectIdentifiers.firesaberkem256r3] = SaberConverter;
            Converters[BCObjectIdentifiers.ulightsaberkemr3] = SaberConverter;
            Converters[BCObjectIdentifiers.usaberkemr3] = SaberConverter;
            Converters[BCObjectIdentifiers.ufiresaberkemr3] = SaberConverter;
            Converters[BCObjectIdentifiers.lightsaberkem90sr3] = SaberConverter;
            Converters[BCObjectIdentifiers.saberkem90sr3] = SaberConverter;
            Converters[BCObjectIdentifiers.firesaberkem90sr3] = SaberConverter;
            Converters[BCObjectIdentifiers.ulightsaberkem90sr3] = SaberConverter;
            Converters[BCObjectIdentifiers.usaberkem90sr3] = SaberConverter;
            Converters[BCObjectIdentifiers.ufiresaberkem90sr3] = SaberConverter;
            
            Converters[BCObjectIdentifiers.picnic] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl1fs] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl1ur] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl3fs] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl3ur] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl5fs] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl5ur] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnic3l1] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnic3l3] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnic3l5] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl1full] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl3full] = PicnicConverter;
            Converters[BCObjectIdentifiers.picnicl5full] = PicnicConverter;

            Converters.Add(BCObjectIdentifiers.ntruhps2048509, NtruConverter);
            Converters.Add(BCObjectIdentifiers.ntruhps2048677, NtruConverter);
            Converters.Add(BCObjectIdentifiers.ntruhps4096821, NtruConverter);
            Converters.Add(BCObjectIdentifiers.ntruhps40961229, NtruConverter);
            Converters.Add(BCObjectIdentifiers.ntruhrss701, NtruConverter);
            Converters.Add(BCObjectIdentifiers.ntruhrss1373, NtruConverter);

#pragma warning disable CS0618 // Type or member is obsolete
            Converters[BCObjectIdentifiers.dilithium2] = DilithiumConverter;
            Converters[BCObjectIdentifiers.dilithium3] = DilithiumConverter;
            Converters[BCObjectIdentifiers.dilithium5] = DilithiumConverter;
            Converters[BCObjectIdentifiers.dilithium2_aes] = DilithiumConverter;
            Converters[BCObjectIdentifiers.dilithium3_aes] = DilithiumConverter;
            Converters[BCObjectIdentifiers.dilithium5_aes] = DilithiumConverter;
#pragma warning restore CS0618 // Type or member is obsolete

            Converters[BCObjectIdentifiers.falcon_512] = FalconConverter;
            Converters[BCObjectIdentifiers.falcon_1024] = FalconConverter;


            Converters[NistObjectIdentifiers.id_alg_ml_kem_512] = MLKemConverter;
            Converters[NistObjectIdentifiers.id_alg_ml_kem_768] = MLKemConverter;
            Converters[NistObjectIdentifiers.id_alg_ml_kem_1024] = MLKemConverter;

            Converters[BCObjectIdentifiers.bike128] = BikeConverter;
            Converters[BCObjectIdentifiers.bike192] = BikeConverter;
            Converters[BCObjectIdentifiers.bike256] = BikeConverter;

            Converters[BCObjectIdentifiers.hqc128] = HqcConverter;
            Converters[BCObjectIdentifiers.hqc192] = HqcConverter;
            Converters[BCObjectIdentifiers.hqc256] = HqcConverter;


#pragma warning disable CS0618 // Type or member is obsolete
            Converters[BCObjectIdentifiers.sphincsPlus] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256f_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256s_r3] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256f_r3] = SphincsPlusConverter;

            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple] = SphincsPlusConverter;

            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_128f] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_128f] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_192f] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_192f] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_sha2_256f] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256s] = SphincsPlusConverter;
            Converters[BCObjectIdentifiers.sphincsPlus_shake_256f] = SphincsPlusConverter;
#pragma warning restore CS0618 // Type or member is obsolete
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
            var algID = keyInfo.Algorithm;
            var algOid = algID.Algorithm;

            if (!Converters.TryGetValue(algOid, out var converter))
                throw new IOException("algorithm identifier in public key not recognised: " + algOid);

            return converter(keyInfo, defaultParams);
        }

#pragma warning disable CS0618 // Type or member is obsolete
        internal static DilithiumPublicKeyParameters GetDilithiumPublicKey(DilithiumParameters dilithiumParameters,
            DerBitString publicKeyData)
        {
            byte[] publicKeyOctets = publicKeyData.GetOctets();
            try
            {
                Asn1Object obj = Asn1Object.FromByteArray(publicKeyOctets);
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
                return new DilithiumPublicKeyParameters(dilithiumParameters, publicKeyOctets);
            }
        }
#pragma warning restore CS0618 // Type or member is obsolete

        private static AsymmetricKeyParameter LmsConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
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

#pragma warning disable CS0618 // Type or member is obsolete
        private static AsymmetricKeyParameter SphincsPlusConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            try
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                SphincsPlusParameters spParams = PqcUtilities.SphincsPlusParamsLookup(keyInfo.Algorithm.Algorithm);

                return new SphincsPlusPublicKeyParameters(spParams, Arrays.CopyOfRange(keyEnc, 4, keyEnc.Length));
            }
            catch (Exception)
            {
                byte[] keyEnc = keyInfo.PublicKey.GetOctets();

                SphincsPlusParameters spParams = PqcUtilities.SphincsPlusParamsLookup(keyInfo.Algorithm.Algorithm);

                return new SphincsPlusPublicKeyParameters(spParams, keyEnc);
            }
        }
#pragma warning restore CS0618 // Type or member is obsolete

        private static AsymmetricKeyParameter CmceConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            byte[] keyEnc = CmcePublicKey.GetInstance(keyInfo.ParsePublicKey()).T;

            CmceParameters spParams = PqcUtilities.McElieceParamsLookup(keyInfo.Algorithm.Algorithm);

            return new CmcePublicKeyParameters(spParams, keyEnc);
        }

        private static AsymmetricKeyParameter FrodoConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

            FrodoParameters fParams = PqcUtilities.FrodoParamsLookup(keyInfo.Algorithm.Algorithm);

            return new FrodoPublicKeyParameters(fParams, keyEnc);
        }

        private static AsymmetricKeyParameter SaberConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            byte[] keyEnc = Asn1OctetString.GetInstance(
                Asn1Sequence.GetInstance(keyInfo.ParsePublicKey())[0]).GetOctets();

            SaberParameters saberParams = PqcUtilities.SaberParamsLookup(keyInfo.Algorithm.Algorithm);

            return new SaberPublicKeyParameters(saberParams, keyEnc);
        }

        private static AsymmetricKeyParameter PicnicConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

            PicnicParameters picnicParams = PqcUtilities.PicnicParamsLookup(keyInfo.Algorithm.Algorithm);

            return new PicnicPublicKeyParameters(picnicParams, keyEnc);
        }

        private static AsymmetricKeyParameter DilithiumConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            var dilithiumParameters = PqcUtilities.DilithiumParamsLookup(keyInfo.Algorithm.Algorithm);

            return GetDilithiumPublicKey(dilithiumParameters, publicKeyData: keyInfo.PublicKey);
        }

        private static AsymmetricKeyParameter MLKemConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            var mlKemParameters = MLKemParameters.ByOid[keyInfo.Algorithm.Algorithm];

            return new MLKemPublicKeyParameters(mlKemParameters, encoding: keyInfo.PublicKey.GetOctets());
        }

        private static AsymmetricKeyParameter NtruConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            var ntruParameters = PqcUtilities.NtruParamsLookup(keyInfo.Algorithm.Algorithm);

            return GetNtruPublicKey(ntruParameters, keyInfo.PublicKey);
        }

        private static NtruPublicKeyParameters GetNtruPublicKey(NtruParameters ntruParameters, DerBitString publicKey)
        {
            if (publicKey.IsOctetAligned())
            {
                //int publicKeyLength = ntruParameters.PublicKeyLength;

                //int bytesLength = publicKey.GetBytesLength();
                //if (bytesLength == publicKeyLength)
                //    // TODO[pqc] Avoid redundant copies?
                //    return new NtruPublicKeyParameters(ntruParameters, key: publicKey.GetOctets());

                // TODO[pqc] Remove support for legacy/prototype formats?
                //if (bytesLength > publicKeyLength)
                {
                    try
                    {
                        Asn1Object obj = Asn1Object.FromMemoryStream(publicKey.GetOctetMemoryStream());
                        if (obj is Asn1OctetString oct)
                        {
                            //if (oct.GetOctetsLength() == publicKeyLength)
                            {
                                return new NtruPublicKeyParameters(ntruParameters, key: oct.GetOctets());
                            }
                        }
                    }
                    catch (Exception)
                    {
                    }
                }

                // TODO[pqc] Avoid redundant copies?
                return new NtruPublicKeyParameters(ntruParameters, key: publicKey.GetOctets());
            }

            throw new ArgumentException("invalid " + ntruParameters.Name + " public key");
        }

        private static AsymmetricKeyParameter FalconConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
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

        private static AsymmetricKeyParameter BikeConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            try
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(keyInfo.Algorithm.Algorithm);

                return new BikePublicKeyParameters(bikeParams, keyEnc);
            }
            catch (Exception)
            {
                byte[] keyEnc = keyInfo.PublicKey.GetOctets();

                BikeParameters bikeParams = PqcUtilities.BikeParamsLookup(keyInfo.Algorithm.Algorithm);

                return new BikePublicKeyParameters(bikeParams, keyEnc);
            }
        }

        private static AsymmetricKeyParameter HqcConverter(SubjectPublicKeyInfo keyInfo, object defaultParams)
        {
            try
            {
                byte[] keyEnc = Asn1OctetString.GetInstance(keyInfo.ParsePublicKey()).GetOctets();

                HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(keyInfo.Algorithm.Algorithm);

                return new HqcPublicKeyParameters(hqcParams, keyEnc);
            }
            catch (Exception)
            {
                // raw encoding
                byte[] keyEnc = keyInfo.PublicKey.GetOctets();

                HqcParameters hqcParams = PqcUtilities.HqcParamsLookup(keyInfo.Algorithm.Algorithm);

                return new HqcPublicKeyParameters(hqcParams, keyEnc);
            }
        }
    }
}
