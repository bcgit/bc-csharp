using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Pqc.Crypto.Bike;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Hqc;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.Utilities
{
    internal class PqcUtilities
    {
        private readonly static Dictionary<CmceParameters, DerObjectIdentifier> mcElieceOids = new Dictionary<CmceParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, CmceParameters> mcElieceParams = new Dictionary<DerObjectIdentifier, CmceParameters>();

        private readonly static Dictionary<FrodoParameters, DerObjectIdentifier> frodoOids = new Dictionary<FrodoParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, FrodoParameters> frodoParams = new Dictionary<DerObjectIdentifier, FrodoParameters>();

        private readonly static Dictionary<SaberParameters, DerObjectIdentifier> saberOids = new Dictionary<SaberParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, SaberParameters> saberParams = new Dictionary<DerObjectIdentifier, SaberParameters>();

        private readonly static Dictionary<PicnicParameters, DerObjectIdentifier> picnicOids = new Dictionary<PicnicParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, PicnicParameters> picnicParams = new Dictionary<DerObjectIdentifier, PicnicParameters>();

#pragma warning disable CS0618 // Type or member is obsolete
        private readonly static Dictionary<SikeParameters, DerObjectIdentifier> sikeOids = new Dictionary<SikeParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, SikeParameters> sikeParams = new Dictionary<DerObjectIdentifier, SikeParameters>();
#pragma warning restore CS0618 // Type or member is obsolete

        private readonly static Dictionary<KyberParameters, DerObjectIdentifier> kyberOids = new Dictionary<KyberParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, KyberParameters> kyberParams = new Dictionary<DerObjectIdentifier, KyberParameters>();

        private readonly static Dictionary<DilithiumParameters, DerObjectIdentifier> dilithiumOids = new Dictionary<DilithiumParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, DilithiumParameters> dilithiumParams = new Dictionary<DerObjectIdentifier, DilithiumParameters>();

        private readonly static Dictionary<FalconParameters, DerObjectIdentifier> falconOids = new Dictionary<FalconParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, FalconParameters> falconParams = new Dictionary<DerObjectIdentifier, FalconParameters>();

        private readonly static Dictionary<BikeParameters, DerObjectIdentifier> bikeOids = new Dictionary<BikeParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, BikeParameters> bikeParams = new Dictionary<DerObjectIdentifier, BikeParameters>();

        private readonly static Dictionary<HqcParameters, DerObjectIdentifier> hqcOids = new Dictionary<HqcParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, HqcParameters> hqcParams = new Dictionary<DerObjectIdentifier, HqcParameters>();

        private readonly static Dictionary<SphincsPlusParameters, DerObjectIdentifier> sphincsPlusOids = new Dictionary<SphincsPlusParameters, DerObjectIdentifier>();
        private readonly static Dictionary<DerObjectIdentifier, SphincsPlusParameters> sphincsPlusParams = new Dictionary<DerObjectIdentifier, SphincsPlusParameters>();

        static PqcUtilities()
        {
            // CMCE
            mcElieceOids[CmceParameters.mceliece348864r3] = BCObjectIdentifiers.mceliece348864_r3;
            mcElieceOids[CmceParameters.mceliece348864fr3] = BCObjectIdentifiers.mceliece348864f_r3;
            mcElieceOids[CmceParameters.mceliece460896r3] = BCObjectIdentifiers.mceliece460896_r3;
            mcElieceOids[CmceParameters.mceliece460896fr3] = BCObjectIdentifiers.mceliece460896f_r3;
            mcElieceOids[CmceParameters.mceliece6688128r3] = BCObjectIdentifiers.mceliece6688128_r3;
            mcElieceOids[CmceParameters.mceliece6688128fr3] = BCObjectIdentifiers.mceliece6688128f_r3;
            mcElieceOids[CmceParameters.mceliece6960119r3] = BCObjectIdentifiers.mceliece6960119_r3;
            mcElieceOids[CmceParameters.mceliece6960119fr3] = BCObjectIdentifiers.mceliece6960119f_r3;
            mcElieceOids[CmceParameters.mceliece8192128r3] = BCObjectIdentifiers.mceliece8192128_r3;
            mcElieceOids[CmceParameters.mceliece8192128fr3] = BCObjectIdentifiers.mceliece8192128f_r3;

            mcElieceParams[BCObjectIdentifiers.mceliece348864_r3] = CmceParameters.mceliece348864r3;
            mcElieceParams[BCObjectIdentifiers.mceliece348864f_r3] = CmceParameters.mceliece348864fr3;
            mcElieceParams[BCObjectIdentifiers.mceliece460896_r3] = CmceParameters.mceliece460896r3;
            mcElieceParams[BCObjectIdentifiers.mceliece460896f_r3] = CmceParameters.mceliece460896fr3;
            mcElieceParams[BCObjectIdentifiers.mceliece6688128_r3] = CmceParameters.mceliece6688128r3;
            mcElieceParams[BCObjectIdentifiers.mceliece6688128f_r3] = CmceParameters.mceliece6688128fr3;
            mcElieceParams[BCObjectIdentifiers.mceliece6960119_r3] = CmceParameters.mceliece6960119r3;
            mcElieceParams[BCObjectIdentifiers.mceliece6960119f_r3] = CmceParameters.mceliece6960119fr3;
            mcElieceParams[BCObjectIdentifiers.mceliece8192128_r3] = CmceParameters.mceliece8192128r3;
            mcElieceParams[BCObjectIdentifiers.mceliece8192128f_r3] = CmceParameters.mceliece8192128fr3;

            frodoOids[FrodoParameters.frodokem640aes] = BCObjectIdentifiers.frodokem640aes;
            frodoOids[FrodoParameters.frodokem640shake] = BCObjectIdentifiers.frodokem640shake;
            frodoOids[FrodoParameters.frodokem976aes] = BCObjectIdentifiers.frodokem976aes;
            frodoOids[FrodoParameters.frodokem976shake] = BCObjectIdentifiers.frodokem976shake;
            frodoOids[FrodoParameters.frodokem1344aes] = BCObjectIdentifiers.frodokem1344aes;
            frodoOids[FrodoParameters.frodokem1344shake] = BCObjectIdentifiers.frodokem1344shake;

            frodoParams[BCObjectIdentifiers.frodokem640aes] = FrodoParameters.frodokem640aes;
            frodoParams[BCObjectIdentifiers.frodokem640shake] = FrodoParameters.frodokem640shake;
            frodoParams[BCObjectIdentifiers.frodokem976aes] = FrodoParameters.frodokem976aes;
            frodoParams[BCObjectIdentifiers.frodokem976shake] = FrodoParameters.frodokem976shake;
            frodoParams[BCObjectIdentifiers.frodokem1344aes] = FrodoParameters.frodokem1344aes;
            frodoParams[BCObjectIdentifiers.frodokem1344shake] = FrodoParameters.frodokem1344shake;

            saberOids[SaberParameters.lightsaberkem128r3] = BCObjectIdentifiers.lightsaberkem128r3;
            saberOids[SaberParameters.saberkem128r3] = BCObjectIdentifiers.saberkem128r3;
            saberOids[SaberParameters.firesaberkem128r3] = BCObjectIdentifiers.firesaberkem128r3;
            saberOids[SaberParameters.lightsaberkem192r3] = BCObjectIdentifiers.lightsaberkem192r3;
            saberOids[SaberParameters.saberkem192r3] = BCObjectIdentifiers.saberkem192r3;
            saberOids[SaberParameters.firesaberkem192r3] = BCObjectIdentifiers.firesaberkem192r3;
            saberOids[SaberParameters.lightsaberkem256r3] = BCObjectIdentifiers.lightsaberkem256r3;
            saberOids[SaberParameters.saberkem256r3] = BCObjectIdentifiers.saberkem256r3;
            saberOids[SaberParameters.firesaberkem256r3] = BCObjectIdentifiers.firesaberkem256r3;
            saberOids[SaberParameters.ulightsaberkemr3] = BCObjectIdentifiers.ulightsaberkemr3;
            saberOids[SaberParameters.usaberkemr3] = BCObjectIdentifiers.usaberkemr3;
            saberOids[SaberParameters.ufiresaberkemr3] = BCObjectIdentifiers.ufiresaberkemr3;
            saberOids[SaberParameters.lightsaberkem90sr3] = BCObjectIdentifiers.lightsaberkem90sr3;
            saberOids[SaberParameters.saberkem90sr3] = BCObjectIdentifiers.saberkem90sr3;
            saberOids[SaberParameters.firesaberkem90sr3] = BCObjectIdentifiers.firesaberkem90sr3;
            saberOids[SaberParameters.ulightsaberkem90sr3] = BCObjectIdentifiers.ulightsaberkem90sr3;
            saberOids[SaberParameters.usaberkem90sr3] = BCObjectIdentifiers.usaberkem90sr3;
            saberOids[SaberParameters.ufiresaberkem90sr3] = BCObjectIdentifiers.ufiresaberkem90sr3;

            saberParams[BCObjectIdentifiers.lightsaberkem128r3] = SaberParameters.lightsaberkem128r3;
            saberParams[BCObjectIdentifiers.saberkem128r3] = SaberParameters.saberkem128r3;
            saberParams[BCObjectIdentifiers.firesaberkem128r3] = SaberParameters.firesaberkem128r3;
            saberParams[BCObjectIdentifiers.lightsaberkem192r3] = SaberParameters.lightsaberkem192r3;
            saberParams[BCObjectIdentifiers.saberkem192r3] = SaberParameters.saberkem192r3;
            saberParams[BCObjectIdentifiers.firesaberkem192r3] = SaberParameters.firesaberkem192r3;
            saberParams[BCObjectIdentifiers.lightsaberkem256r3] = SaberParameters.lightsaberkem256r3;
            saberParams[BCObjectIdentifiers.saberkem256r3] = SaberParameters.saberkem256r3;
            saberParams[BCObjectIdentifiers.firesaberkem256r3] = SaberParameters.firesaberkem256r3;
            saberParams[BCObjectIdentifiers.ulightsaberkemr3] = SaberParameters.ulightsaberkemr3;
            saberParams[BCObjectIdentifiers.usaberkemr3] = SaberParameters.usaberkemr3;
            saberParams[BCObjectIdentifiers.ufiresaberkemr3] = SaberParameters.ufiresaberkemr3;
            saberParams[BCObjectIdentifiers.lightsaberkem90sr3] = SaberParameters.lightsaberkem90sr3;
            saberParams[BCObjectIdentifiers.saberkem90sr3] = SaberParameters.saberkem90sr3;
            saberParams[BCObjectIdentifiers.firesaberkem90sr3] = SaberParameters.firesaberkem90sr3;
            saberParams[BCObjectIdentifiers.ulightsaberkem90sr3] = SaberParameters.ulightsaberkem90sr3;
            saberParams[BCObjectIdentifiers.usaberkem90sr3] = SaberParameters.usaberkem90sr3;
            saberParams[BCObjectIdentifiers.ufiresaberkem90sr3] = SaberParameters.ufiresaberkem90sr3;
            
            picnicOids[PicnicParameters.picnicl1fs] = BCObjectIdentifiers.picnicl1fs;
            picnicOids[PicnicParameters.picnicl1ur] = BCObjectIdentifiers.picnicl1ur;
            picnicOids[PicnicParameters.picnicl3fs] = BCObjectIdentifiers.picnicl3fs;
            picnicOids[PicnicParameters.picnicl3ur] = BCObjectIdentifiers.picnicl3ur;
            picnicOids[PicnicParameters.picnicl5fs] = BCObjectIdentifiers.picnicl5fs;
            picnicOids[PicnicParameters.picnicl5ur] = BCObjectIdentifiers.picnicl5ur;
            picnicOids[PicnicParameters.picnic3l1] = BCObjectIdentifiers.picnic3l1;
            picnicOids[PicnicParameters.picnic3l3] = BCObjectIdentifiers.picnic3l3;
            picnicOids[PicnicParameters.picnic3l5] = BCObjectIdentifiers.picnic3l5;
            picnicOids[PicnicParameters.picnicl1full] = BCObjectIdentifiers.picnicl1full;
            picnicOids[PicnicParameters.picnicl3full] = BCObjectIdentifiers.picnicl3full;
            picnicOids[PicnicParameters.picnicl5full] = BCObjectIdentifiers.picnicl5full;
    
            picnicParams[BCObjectIdentifiers.picnicl1fs] = PicnicParameters.picnicl1fs;
            picnicParams[BCObjectIdentifiers.picnicl1ur] = PicnicParameters.picnicl1ur;
            picnicParams[BCObjectIdentifiers.picnicl3fs] = PicnicParameters.picnicl3fs;
            picnicParams[BCObjectIdentifiers.picnicl3ur] = PicnicParameters.picnicl3ur;
            picnicParams[BCObjectIdentifiers.picnicl5fs] = PicnicParameters.picnicl5fs;
            picnicParams[BCObjectIdentifiers.picnicl5ur] = PicnicParameters.picnicl5ur;
            picnicParams[BCObjectIdentifiers.picnic3l1] = PicnicParameters.picnic3l1;
            picnicParams[BCObjectIdentifiers.picnic3l3] = PicnicParameters.picnic3l3;
            picnicParams[BCObjectIdentifiers.picnic3l5] = PicnicParameters.picnic3l5;
            picnicParams[BCObjectIdentifiers.picnicl1full] = PicnicParameters.picnicl1full;
            picnicParams[BCObjectIdentifiers.picnicl3full] = PicnicParameters.picnicl3full;
            picnicParams[BCObjectIdentifiers.picnicl5full] = PicnicParameters.picnicl5full;

#pragma warning disable CS0618 // Type or member is obsolete
            sikeParams[BCObjectIdentifiers.sikep434] = SikeParameters.sikep434;
            sikeParams[BCObjectIdentifiers.sikep503] = SikeParameters.sikep503;
            sikeParams[BCObjectIdentifiers.sikep610] = SikeParameters.sikep610;
            sikeParams[BCObjectIdentifiers.sikep751] = SikeParameters.sikep751;
            sikeParams[BCObjectIdentifiers.sikep434_compressed] = SikeParameters.sikep434_compressed;
            sikeParams[BCObjectIdentifiers.sikep503_compressed] = SikeParameters.sikep503_compressed;
            sikeParams[BCObjectIdentifiers.sikep610_compressed] = SikeParameters.sikep610_compressed;
            sikeParams[BCObjectIdentifiers.sikep751_compressed] = SikeParameters.sikep751_compressed;

            sikeOids[SikeParameters.sikep434] = BCObjectIdentifiers.sikep434;
            sikeOids[SikeParameters.sikep503] = BCObjectIdentifiers.sikep503;
            sikeOids[SikeParameters.sikep610] = BCObjectIdentifiers.sikep610;
            sikeOids[SikeParameters.sikep751] = BCObjectIdentifiers.sikep751;
            sikeOids[SikeParameters.sikep434_compressed] = BCObjectIdentifiers.sikep434_compressed;
            sikeOids[SikeParameters.sikep503_compressed] = BCObjectIdentifiers.sikep503_compressed;
            sikeOids[SikeParameters.sikep610_compressed] = BCObjectIdentifiers.sikep610_compressed;
            sikeOids[SikeParameters.sikep751_compressed] = BCObjectIdentifiers.sikep751_compressed;
#pragma warning restore CS0618 // Type or member is obsolete

            kyberOids[KyberParameters.kyber512] = BCObjectIdentifiers.kyber512;
            kyberOids[KyberParameters.kyber768] = BCObjectIdentifiers.kyber768;
            kyberOids[KyberParameters.kyber1024] = BCObjectIdentifiers.kyber1024;
            kyberOids[KyberParameters.kyber512_aes] = BCObjectIdentifiers.kyber512_aes;
            kyberOids[KyberParameters.kyber768_aes] = BCObjectIdentifiers.kyber768_aes;
            kyberOids[KyberParameters.kyber1024_aes] = BCObjectIdentifiers.kyber1024_aes;   
            
            kyberParams[BCObjectIdentifiers.kyber512] = KyberParameters.kyber512;
            kyberParams[BCObjectIdentifiers.kyber768] = KyberParameters.kyber768;
            kyberParams[BCObjectIdentifiers.kyber1024] = KyberParameters.kyber1024;
            kyberParams[BCObjectIdentifiers.kyber512_aes] = KyberParameters.kyber512_aes;
            kyberParams[BCObjectIdentifiers.kyber768_aes] = KyberParameters.kyber768_aes;
            kyberParams[BCObjectIdentifiers.kyber1024_aes] = KyberParameters.kyber1024_aes;
            
            
            falconOids[FalconParameters.falcon_512] = BCObjectIdentifiers.falcon_512;
            falconOids[FalconParameters.falcon_1024] = BCObjectIdentifiers.falcon_1024;
            
            falconParams[BCObjectIdentifiers.falcon_512] = FalconParameters.falcon_512;
            falconParams[BCObjectIdentifiers.falcon_1024] = FalconParameters.falcon_1024;
            
            dilithiumOids[DilithiumParameters.Dilithium2] = BCObjectIdentifiers.dilithium2;
            dilithiumOids[DilithiumParameters.Dilithium3] = BCObjectIdentifiers.dilithium3;
            dilithiumOids[DilithiumParameters.Dilithium5] = BCObjectIdentifiers.dilithium5;
            dilithiumOids[DilithiumParameters.Dilithium2Aes] = BCObjectIdentifiers.dilithium2_aes;
            dilithiumOids[DilithiumParameters.Dilithium3Aes] = BCObjectIdentifiers.dilithium3_aes;
            dilithiumOids[DilithiumParameters.Dilithium5Aes] = BCObjectIdentifiers.dilithium5_aes;
            
            dilithiumParams[BCObjectIdentifiers.dilithium2] = DilithiumParameters.Dilithium2;
            dilithiumParams[BCObjectIdentifiers.dilithium3] = DilithiumParameters.Dilithium3;
            dilithiumParams[BCObjectIdentifiers.dilithium5] = DilithiumParameters.Dilithium5;
            dilithiumParams[BCObjectIdentifiers.dilithium2_aes] = DilithiumParameters.Dilithium2Aes;
            dilithiumParams[BCObjectIdentifiers.dilithium3_aes] = DilithiumParameters.Dilithium3Aes;
            dilithiumParams[BCObjectIdentifiers.dilithium5_aes] = DilithiumParameters.Dilithium5Aes;

            bikeParams[BCObjectIdentifiers.bike128] = BikeParameters.bike128;
            bikeParams[BCObjectIdentifiers.bike192] = BikeParameters.bike192;
            bikeParams[BCObjectIdentifiers.bike256] = BikeParameters.bike256;

            bikeOids[BikeParameters.bike128] = BCObjectIdentifiers.bike128;
            bikeOids[BikeParameters.bike192] = BCObjectIdentifiers.bike192;
            bikeOids[BikeParameters.bike256] = BCObjectIdentifiers.bike256;

            hqcParams[BCObjectIdentifiers.hqc128] = HqcParameters.hqc128;
            hqcParams[BCObjectIdentifiers.hqc192] = HqcParameters.hqc192;
            hqcParams[BCObjectIdentifiers.hqc256] = HqcParameters.hqc256;

            hqcOids[HqcParameters.hqc128] = BCObjectIdentifiers.hqc128;
            hqcOids[HqcParameters.hqc192] = BCObjectIdentifiers.hqc192;
            hqcOids[HqcParameters.hqc256] = BCObjectIdentifiers.hqc256;

            sphincsPlusOids[SphincsPlusParameters.sha2_128s] = BCObjectIdentifiers.sphincsPlus_sha2_128s_r3;
            sphincsPlusOids[SphincsPlusParameters.sha2_128f] = BCObjectIdentifiers.sphincsPlus_sha2_128f_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_128s] = BCObjectIdentifiers.sphincsPlus_shake_128s_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_128f] = BCObjectIdentifiers.sphincsPlus_shake_128f_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_128s] = BCObjectIdentifiers.sphincsPlus_haraka_128s_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_128f] = BCObjectIdentifiers.sphincsPlus_haraka_128f_r3;
            sphincsPlusOids[SphincsPlusParameters.sha2_192s] = BCObjectIdentifiers.sphincsPlus_sha2_192s_r3;
            sphincsPlusOids[SphincsPlusParameters.sha2_192f] = BCObjectIdentifiers.sphincsPlus_sha2_192f_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_192s] = BCObjectIdentifiers.sphincsPlus_shake_192s_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_192f] = BCObjectIdentifiers.sphincsPlus_shake_192f_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_192s] = BCObjectIdentifiers.sphincsPlus_haraka_192s_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_192f] = BCObjectIdentifiers.sphincsPlus_haraka_192f_r3;
            sphincsPlusOids[SphincsPlusParameters.sha2_256s] = BCObjectIdentifiers.sphincsPlus_sha2_256s_r3;
            sphincsPlusOids[SphincsPlusParameters.sha2_256f] = BCObjectIdentifiers.sphincsPlus_sha2_256f_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_256s] = BCObjectIdentifiers.sphincsPlus_shake_256s_r3;
            sphincsPlusOids[SphincsPlusParameters.shake_256f] = BCObjectIdentifiers.sphincsPlus_shake_256f_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_256s] = BCObjectIdentifiers.sphincsPlus_haraka_256s_r3;
            sphincsPlusOids[SphincsPlusParameters.haraka_256f] = BCObjectIdentifiers.sphincsPlus_haraka_256f_r3;

            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_128s_r3] = SphincsPlusParameters.sha2_128s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_128f_r3] = SphincsPlusParameters.sha2_128f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_128s_r3] = SphincsPlusParameters.shake_128s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_128f_r3] = SphincsPlusParameters.shake_128f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_128s_r3] = SphincsPlusParameters.haraka_128s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_128f_r3] = SphincsPlusParameters.haraka_128f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_192s_r3] = SphincsPlusParameters.sha2_192s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_192f_r3] = SphincsPlusParameters.sha2_192f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_192s_r3] = SphincsPlusParameters.shake_192s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_192f_r3] = SphincsPlusParameters.shake_192f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_192s_r3] = SphincsPlusParameters.haraka_192s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_192f_r3] = SphincsPlusParameters.haraka_192f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_256s_r3] = SphincsPlusParameters.sha2_256s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_sha2_256f_r3] = SphincsPlusParameters.sha2_256f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_256s_r3] = SphincsPlusParameters.shake_256s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_shake_256f_r3] = SphincsPlusParameters.shake_256f;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_256s_r3] = SphincsPlusParameters.haraka_256s;
            sphincsPlusParams[BCObjectIdentifiers.sphincsPlus_haraka_256f_r3] = SphincsPlusParameters.haraka_256f;
        }

        internal static DerObjectIdentifier McElieceOidLookup(CmceParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(mcElieceOids, parameters);
        }

        internal static CmceParameters McElieceParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(mcElieceParams, oid);
        }

        internal static DerObjectIdentifier FrodoOidLookup(FrodoParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(frodoOids, parameters);
        }

        internal static FrodoParameters FrodoParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(frodoParams, oid);
        }

        internal static DerObjectIdentifier SaberOidLookup(SaberParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(saberOids, parameters);
        }

        internal static SaberParameters SaberParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(saberParams, oid);
        }

        internal static KyberParameters KyberParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(kyberParams, oid);
        }

        internal static DerObjectIdentifier KyberOidLookup(KyberParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(kyberOids, parameters);
        }

        internal static FalconParameters FalconParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(falconParams, oid);
        }       

        internal static DerObjectIdentifier FalconOidLookup(FalconParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(falconOids, parameters);
        }

        internal static DilithiumParameters DilithiumParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(dilithiumParams, oid);
        }

        internal static DerObjectIdentifier DilithiumOidLookup(DilithiumParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(dilithiumOids, parameters);
        }

        internal static DerObjectIdentifier PicnicOidLookup(PicnicParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(picnicOids, parameters);
        }

        internal static PicnicParameters PicnicParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(picnicParams, oid);
        }

#pragma warning disable CS0618 // Type or member is obsolete
        internal static DerObjectIdentifier SikeOidLookup(SikeParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(sikeOids, parameters);
        }

        internal static SikeParameters SikeParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(sikeParams, oid);
        }
#pragma warning restore CS0618 // Type or member is obsolete

        internal static DerObjectIdentifier BikeOidLookup(BikeParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(bikeOids, parameters);
        }

        internal static BikeParameters BikeParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(bikeParams, oid);
        }

        internal static DerObjectIdentifier HqcOidLookup(HqcParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(hqcOids, parameters);
        }

        internal static HqcParameters HqcParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(hqcParams, oid);
        }

        internal static DerObjectIdentifier SphincsPlusOidLookup(SphincsPlusParameters parameters)
        {
            return CollectionUtilities.GetValueOrNull(sphincsPlusOids, parameters);
        }

        internal static SphincsPlusParameters SphincsPlusParamsLookup(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(sphincsPlusParams, oid);
        }
    }
}
