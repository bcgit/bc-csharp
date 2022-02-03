using System;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    public class SPHINCSPlusParameters
    {
        public static SPHINCSPlusParameters sha256_128f = new SPHINCSPlusParameters("sha256-128f-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 22, 6, 33, 66));

        public static SPHINCSPlusParameters sha256_128s = new SPHINCSPlusParameters("sha256-128s-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 16, 16, 7, 12, 14, 63));

        public static SPHINCSPlusParameters sha256_192f = new SPHINCSPlusParameters("sha256-192f-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 22, 8, 33, 66));

        public static SPHINCSPlusParameters sha256_192s = new SPHINCSPlusParameters("sha256-192s-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 24, 16, 7, 14, 17, 63));

        public static SPHINCSPlusParameters sha256_256f = new SPHINCSPlusParameters("sha256-256f-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 17, 9, 35, 68));

        public static SPHINCSPlusParameters sha256_256s = new SPHINCSPlusParameters("sha256-256s-robust",
            new SPHINCSPlusEngine.Sha256Engine(true, 32, 16, 8, 14, 22, 64));

        public static SPHINCSPlusParameters sha256_128f_simple = new SPHINCSPlusParameters("sha256-128f-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 22, 6, 33, 66));

        public static SPHINCSPlusParameters sha256_128s_simple = new SPHINCSPlusParameters("sha256-128s-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 16, 16, 7, 12, 14, 63));

        public static SPHINCSPlusParameters sha256_192f_simple = new SPHINCSPlusParameters("sha256-192f-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 22, 8, 33, 66));

        public static SPHINCSPlusParameters sha256_192s_simple = new SPHINCSPlusParameters("sha256-192s-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 24, 16, 7, 14, 17, 63));

        public static SPHINCSPlusParameters sha256_256f_simple = new SPHINCSPlusParameters("sha256-256f-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 17, 9, 35, 68));

        public static SPHINCSPlusParameters sha256_256s_simple = new SPHINCSPlusParameters("sha256-256s-simple",
            new SPHINCSPlusEngine.Sha256Engine(false, 32, 16, 8, 14, 22, 64));

        // SHAKE-256.

        public static SPHINCSPlusParameters shake256_128f = new SPHINCSPlusParameters("shake256-128f-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 22, 6, 33, 66));

        public static SPHINCSPlusParameters shake256_128s = new SPHINCSPlusParameters("shake256-128s-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 16, 16, 7, 12, 14, 63));

        public static SPHINCSPlusParameters shake256_192f = new SPHINCSPlusParameters("shake256-192f-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 22, 8, 33, 66));

        public static SPHINCSPlusParameters shake256_192s = new SPHINCSPlusParameters("shake256-192s-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 24, 16, 7, 14, 17, 63));

        public static SPHINCSPlusParameters shake256_256f = new SPHINCSPlusParameters("shake256-256f-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 17, 9, 35, 68));

        public static SPHINCSPlusParameters shake256_256s = new SPHINCSPlusParameters("shake256-256s-robust",
            new SPHINCSPlusEngine.Shake256Engine(true, 32, 16, 8, 14, 22, 64));

        public static SPHINCSPlusParameters shake256_128f_simple = new SPHINCSPlusParameters("shake256-128f-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 22, 6, 33, 66));

        public static SPHINCSPlusParameters shake256_128s_simple = new SPHINCSPlusParameters("shake256-128s-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 16, 16, 7, 12, 14, 63));

        public static SPHINCSPlusParameters shake256_192f_simple = new SPHINCSPlusParameters("shake256-192f-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 22, 8, 33, 66));

        public static SPHINCSPlusParameters shake256_192s_simple = new SPHINCSPlusParameters("shake256-192s-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 24, 16, 7, 14, 17, 63));

        public static SPHINCSPlusParameters shake256_256f_simple = new SPHINCSPlusParameters("shake256-256f-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 17, 9, 35, 68));

        public static SPHINCSPlusParameters shake256_256s_simple = new SPHINCSPlusParameters("shake256-256s-simple",
            new SPHINCSPlusEngine.Shake256Engine(false, 32, 16, 8, 14, 22, 64));

        private static uint sphincsPlus_sha256_128f_robust = 0x010101;
        private static uint sphincsPlus_sha256_128s_robust = 0x010102;
        private static uint sphincsPlus_sha256_192f_robust = 0x010103;
        private static uint sphincsPlus_sha256_192s_robust = 0x010104;
        private static uint sphincsPlus_sha256_256f_robust = 0x010105;
        private static uint sphincsPlus_sha256_256s_robust = 0x010106;
        
        private static uint sphincsPlus_sha256_128f_simple = 0x010201;
        private static uint sphincsPlus_sha256_128s_simple = 0x010202;
        private static uint sphincsPlus_sha256_192f_simple = 0x010203;
        private static uint sphincsPlus_sha256_192s_simple = 0x010204;
        private static uint sphincsPlus_sha256_256f_simple = 0x010205;
        private static uint sphincsPlus_sha256_256s_simple = 0x010206;
        
        private static uint sphincsPlus_shake256_128f_robust = 0x020101;
        private static uint sphincsPlus_shake256_128s_robust = 0x020102;
        private static uint sphincsPlus_shake256_192f_robust = 0x020103;
        private static uint sphincsPlus_shake256_192s_robust = 0x020104;
        private static uint sphincsPlus_shake256_256f_robust = 0x020105;
        private static uint sphincsPlus_shake256_256s_robust = 0x020106;
        
        private static uint sphincsPlus_shake256_128f_simple = 0x020201;
        private static uint sphincsPlus_shake256_128s_simple = 0x020202;
        private static uint sphincsPlus_shake256_192f_simple = 0x020203;
        private static uint sphincsPlus_shake256_192s_simple = 0x020204;
        private static uint sphincsPlus_shake256_256f_simple = 0x020205;
        private static uint sphincsPlus_shake256_256s_simple = 0x020206;

        private static Dictionary<uint, SPHINCSPlusParameters> oidToParams = new Dictionary<uint, SPHINCSPlusParameters>();
        private static Dictionary<SPHINCSPlusParameters, uint> paramsToOid = new Dictionary<SPHINCSPlusParameters, uint>();

        static SPHINCSPlusParameters()
        {
            oidToParams[sphincsPlus_sha256_128f_robust] = SPHINCSPlusParameters.sha256_128f;
            oidToParams[sphincsPlus_sha256_128s_robust] = SPHINCSPlusParameters.sha256_128s;
            oidToParams[sphincsPlus_sha256_192f_robust] = SPHINCSPlusParameters.sha256_192f;
            oidToParams[sphincsPlus_sha256_192s_robust] = SPHINCSPlusParameters.sha256_192s;
            oidToParams[sphincsPlus_sha256_256f_robust] = SPHINCSPlusParameters.sha256_256f;
            oidToParams[sphincsPlus_sha256_256s_robust] = SPHINCSPlusParameters.sha256_256s;

            oidToParams[sphincsPlus_sha256_128f_simple] = SPHINCSPlusParameters.sha256_128f_simple;
            oidToParams[sphincsPlus_sha256_128s_simple] = SPHINCSPlusParameters.sha256_128s_simple;
            oidToParams[sphincsPlus_sha256_192f_simple] = SPHINCSPlusParameters.sha256_192f_simple;
            oidToParams[sphincsPlus_sha256_192s_simple] = SPHINCSPlusParameters.sha256_192s_simple;
            oidToParams[sphincsPlus_sha256_256f_simple] = SPHINCSPlusParameters.sha256_256f_simple;
            oidToParams[sphincsPlus_sha256_256s_simple] = SPHINCSPlusParameters.sha256_256s_simple;

            oidToParams[sphincsPlus_shake256_128f_robust] = SPHINCSPlusParameters.shake256_128f;
            oidToParams[sphincsPlus_shake256_128s_robust] = SPHINCSPlusParameters.shake256_128s;
            oidToParams[sphincsPlus_shake256_192f_robust] = SPHINCSPlusParameters.shake256_192f;
            oidToParams[sphincsPlus_shake256_192s_robust] = SPHINCSPlusParameters.shake256_192s;
            oidToParams[sphincsPlus_shake256_256f_robust] = SPHINCSPlusParameters.shake256_256f;
            oidToParams[sphincsPlus_shake256_256s_robust] = SPHINCSPlusParameters.shake256_256s;

            oidToParams[sphincsPlus_shake256_128f_simple] = SPHINCSPlusParameters.shake256_128f_simple;
            oidToParams[sphincsPlus_shake256_128s_simple] = SPHINCSPlusParameters.shake256_128s_simple;
            oidToParams[sphincsPlus_shake256_192f_simple] = SPHINCSPlusParameters.shake256_192f_simple;
            oidToParams[sphincsPlus_shake256_192s_simple] = SPHINCSPlusParameters.shake256_192s_simple;
            oidToParams[sphincsPlus_shake256_256f_simple] = SPHINCSPlusParameters.shake256_256f_simple;
            oidToParams[sphincsPlus_shake256_256s_simple] = SPHINCSPlusParameters.shake256_256s_simple;

            paramsToOid[SPHINCSPlusParameters.sha256_128f] = sphincsPlus_sha256_128f_robust;
            paramsToOid[SPHINCSPlusParameters.sha256_128s] = sphincsPlus_sha256_128s_robust;
            paramsToOid[SPHINCSPlusParameters.sha256_192f] = sphincsPlus_sha256_192f_robust;
            paramsToOid[SPHINCSPlusParameters.sha256_192s] = sphincsPlus_sha256_192s_robust;
            paramsToOid[SPHINCSPlusParameters.sha256_256f] = sphincsPlus_sha256_256f_robust;
            paramsToOid[SPHINCSPlusParameters.sha256_256s] = sphincsPlus_sha256_256s_robust;

            paramsToOid[SPHINCSPlusParameters.sha256_128f_simple] = sphincsPlus_sha256_128f_simple;
            paramsToOid[SPHINCSPlusParameters.sha256_128s_simple] = sphincsPlus_sha256_128s_simple;
            paramsToOid[SPHINCSPlusParameters.sha256_192f_simple] = sphincsPlus_sha256_192f_simple;
            paramsToOid[SPHINCSPlusParameters.sha256_192s_simple] = sphincsPlus_sha256_192s_simple;
            paramsToOid[SPHINCSPlusParameters.sha256_256f_simple] = sphincsPlus_sha256_256f_simple;
            paramsToOid[SPHINCSPlusParameters.sha256_256s_simple] = sphincsPlus_sha256_256s_simple;

            paramsToOid[SPHINCSPlusParameters.shake256_128f] =  sphincsPlus_shake256_128f_robust;
            paramsToOid[SPHINCSPlusParameters.shake256_128s] =  sphincsPlus_shake256_128s_robust;
            paramsToOid[SPHINCSPlusParameters.shake256_192f] =  sphincsPlus_shake256_192f_robust;
            paramsToOid[SPHINCSPlusParameters.shake256_192s] =  sphincsPlus_shake256_192s_robust;
            paramsToOid[SPHINCSPlusParameters.shake256_256f] =  sphincsPlus_shake256_256f_robust;
            paramsToOid[SPHINCSPlusParameters.shake256_256s] =  sphincsPlus_shake256_256s_robust;

            paramsToOid[SPHINCSPlusParameters.shake256_128f_simple] = sphincsPlus_shake256_128f_simple;
            paramsToOid[SPHINCSPlusParameters.shake256_128s_simple] = sphincsPlus_shake256_128s_simple;
            paramsToOid[SPHINCSPlusParameters.shake256_192f_simple] = sphincsPlus_shake256_192f_simple;
            paramsToOid[SPHINCSPlusParameters.shake256_192s_simple] = sphincsPlus_shake256_192s_simple;
            paramsToOid[SPHINCSPlusParameters.shake256_256f_simple] = sphincsPlus_shake256_256f_simple;
            paramsToOid[SPHINCSPlusParameters.shake256_256s_simple] = sphincsPlus_shake256_256s_simple;
        }

        private String name;
        private SPHINCSPlusEngine engine;

        private SPHINCSPlusParameters(String name, SPHINCSPlusEngine engine)
        {
            this.name = name;
            this.engine = engine;
        }

        public String Name => name;

        internal SPHINCSPlusEngine Engine => engine;

        /**
         * Return the SPHINCS+ parameters that map to the passed in parameter ID.
         * 
         * @param id the oid of interest.
         * @return the parameter set.
         */
        public static SPHINCSPlusParameters GetParams(uint id)
        {
            return (SPHINCSPlusParameters) oidToParams[id];
        }

        /**
         * Return the OID that maps to the passed in SPHINCS+ parameters.
         *
         * @param params the parameters of interest.
         * @return the OID for the parameter set.
         */
        public static uint GetID(SPHINCSPlusParameters parameters)
        {
            return paramsToOid[parameters];
        }

        public byte[] GetEncoded()
        {
            return Pack.UInt32_To_BE(GetID(this));
        }
    }
}