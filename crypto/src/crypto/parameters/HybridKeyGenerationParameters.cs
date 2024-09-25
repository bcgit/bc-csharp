using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.MLKem;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.crypto.parameters
{
    public class HybridKeyGenerationParameters
        : KeyGenerationParameters
    {
        public Dictionary<string, DerObjectIdentifier> classicalNameToOid = new Dictionary<string, DerObjectIdentifier>()
        {
            { "p256", SecObjectIdentifiers.SecP256r1 },
            { "p384", SecObjectIdentifiers.SecP384r1 },
            { "p521", SecObjectIdentifiers.SecP521r1 },
            { "x25519", EdECObjectIdentifiers.id_X25519 },
            { "x448", EdECObjectIdentifiers.id_X448 },
            { "ed25519", EdECObjectIdentifiers.id_Ed25519 },
            { "ed448", EdECObjectIdentifiers.id_Ed448 },
        };

        public Dictionary<DerObjectIdentifier, string> classicalOidToName = new Dictionary<DerObjectIdentifier, string>()
        {
            { SecObjectIdentifiers.SecP256r1, "p256" },
            { SecObjectIdentifiers.SecP384r1, "p384" },
            { SecObjectIdentifiers.SecP521r1, "p521" },
            { EdECObjectIdentifiers.id_X25519, "x25519" },
            { EdECObjectIdentifiers.id_X448, "x448" },
            { EdECObjectIdentifiers.id_Ed25519, "ed25519" },
            { EdECObjectIdentifiers.id_Ed448, "ed448" },
        };

        public Dictionary<string, DerObjectIdentifier> postQuantumNameToOid = new Dictionary<string, DerObjectIdentifier>()
        {
            { "mlkem512", NistObjectIdentifiers.id_alg_ml_kem_512 },
            { "mlkem768", NistObjectIdentifiers.id_alg_ml_kem_768 },
            { "mlkem1024", NistObjectIdentifiers.id_alg_ml_kem_1024 },
            { "mldsa44", NistObjectIdentifiers.id_hash_ml_dsa_44_with_sha512 },
            { "mldsa65", NistObjectIdentifiers.id_hash_ml_dsa_65_with_sha512 },
            { "mldsa87", NistObjectIdentifiers.id_hash_ml_dsa_87_with_sha512 },
            { "slhdsasha2128f", NistObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256 },
            { "slhdsasha2192f", NistObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512 },
            { "slhdsasha2256f", NistObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512 },
            { "slhdsasha2128s", NistObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256 },
            { "slhdsasha2192s", NistObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512 },
            { "slhdsasha2256s", NistObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512 },
            { "slhdsashake128f", NistObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128 },
            { "slhdsashake192f", NistObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256 },
            { "slhdsashake256f", NistObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256 },
            { "slhdsashake128s", NistObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128 },
            { "slhdsashake192s", NistObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256 },
            { "slhdsashake256s", NistObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256 },
        };

        public Dictionary<DerObjectIdentifier, string> postQuantumOidToName = new Dictionary<DerObjectIdentifier, string>()
        {
            { NistObjectIdentifiers.id_alg_ml_kem_512, "mlkem512" },
            { NistObjectIdentifiers.id_alg_ml_kem_768 , "mlkem768" },
            { NistObjectIdentifiers.id_alg_ml_kem_1024 , "mlkem1024" },
            { NistObjectIdentifiers.id_hash_ml_dsa_44_with_sha512 , "mldsa44" },
            { NistObjectIdentifiers.id_hash_ml_dsa_65_with_sha512 , "mldsa65" },
            { NistObjectIdentifiers.id_hash_ml_dsa_87_with_sha512 , "mldsa87" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256 , "slhdsasha2128f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512 , "slhdsasha2192f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512 , "slhdsasha2256f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256 , "slhdsasha2128s" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512 , "slhdsasha2192s" },
            { NistObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512 , "slhdsasha2256s" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128 , "slhdsashake128f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256 , "slhdsashake192f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256 , "slhdsashake256f" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128 , "slhdsashake128s" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256 , "slhdsashake192s" },
            { NistObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256 , "slhdsashake256s" },
        };

        public DerObjectIdentifier ClassicalAlgorithm {  get; set; }

        public DerObjectIdentifier PostQuantumAlgorithm { get; set; }

        public DerObjectIdentifier HybridAlgorithm {  get; set; }

        public string ClassicalName {  get; set; }

        public string PostQuantumName {  get; set; }

        public string HybridName {  get; set; }

        public KeyGenerationParameters ClassicalParameters { get; set; }

        public KeyGenerationParameters PostQuantumParameters { get; set; }

        public HybridKeyGenerationParameters(SecureRandom random, DerObjectIdentifier classicalAlgorithm, DerObjectIdentifier postQuantumAlgorithm)
            : base(random, 256)
        {
            if (!classicalOidToName.ContainsKey(classicalAlgorithm))
            {
                throw new ArgumentException("Unsupported classical algorithm");
            }
            if (!postQuantumOidToName.ContainsKey(postQuantumAlgorithm))
            {
                throw new ArgumentException("Unsupported post-quantum algorithm");
            }

            ClassicalAlgorithm = classicalAlgorithm;
            PostQuantumAlgorithm = postQuantumAlgorithm;

            ClassicalName = classicalOidToName[classicalAlgorithm];
            PostQuantumName = postQuantumOidToName[postQuantumAlgorithm];

            SetHybrid();

            InitializeParameters();
        }

        public HybridKeyGenerationParameters(SecureRandom random, string classicalAlgorithm, string postQuantumAlgorithm)
            : base(random, 256)
        {
            classicalAlgorithm = classicalAlgorithm.ToLowerInvariant();
            postQuantumAlgorithm = postQuantumAlgorithm.ToLowerInvariant();

            if (!classicalNameToOid.ContainsKey(classicalAlgorithm))
            {
                throw new ArgumentException("Unsupported classical algorithm");
            }
            if (!postQuantumNameToOid.ContainsKey(postQuantumAlgorithm))
            {
                throw new ArgumentException("Unsupported post-quantum algorithm");
            }

            ClassicalName = classicalAlgorithm;
            PostQuantumName = postQuantumAlgorithm;

            ClassicalAlgorithm = classicalNameToOid[classicalAlgorithm];
            PostQuantumAlgorithm = postQuantumNameToOid[postQuantumAlgorithm];

            SetHybrid();

            InitializeParameters();
        }

        public HybridKeyGenerationParameters(SecureRandom random, DerObjectIdentifier hybridAlgorithm)
            : base(random, 256)
        {
            if (!HybridParameters.HybridOidToName.ContainsKey(hybridAlgorithm.Id))
            {
                throw new ArgumentException("Unsupported hybrid combination");
            }

            HybridName = HybridParameters.HybridOidToName[hybridAlgorithm.Id];
            HybridAlgorithm = hybridAlgorithm;

            SetClassicals();

            InitializeParameters();
        }

        public HybridKeyGenerationParameters(SecureRandom random, string hybridAlgorithm)
            : base(random, 256)
        {
            hybridAlgorithm = hybridAlgorithm.ToLowerInvariant();

            if (!HybridParameters.HybridNameToOid.ContainsKey(hybridAlgorithm))
            {
                throw new ArgumentException("Unsupported hybrid combination");
            }

            HybridName = hybridAlgorithm;
            HybridAlgorithm = new DerObjectIdentifier(HybridParameters.HybridNameToOid[hybridAlgorithm]);

            SetClassicals();

            InitializeParameters();
        }

        private void SetClassicals()
        {
            var names = HybridName.Split(Convert.ToChar("_"));
            ClassicalName = names[0];
            PostQuantumName = names[1];

            ClassicalAlgorithm = classicalNameToOid[ClassicalName];
            PostQuantumAlgorithm = postQuantumNameToOid[PostQuantumName];
        }

        private void SetHybrid()
        {
            HybridName = string.Concat(ClassicalName, "_", PostQuantumName);

            if (!HybridParameters.HybridNameToOid.ContainsKey(HybridName))
            {
                throw new Exception("Unsupported hybrid combination");
            }

            HybridAlgorithm = new DerObjectIdentifier(HybridParameters.HybridNameToOid[HybridName]);
        }

        private void InitializeParameters()
        {
            switch (ClassicalName)
            {
                case "p256":
                case "p384":
                case "p521":
                    ClassicalParameters = new ECKeyGenerationParameters(ClassicalAlgorithm, new Security.SecureRandom());
                    break;
                case "x25519":
                    ClassicalParameters = new X25519KeyGenerationParameters(new SecureRandom());
                    break;
                case "x448":
                    ClassicalParameters = new X448KeyGenerationParameters(new SecureRandom());
                    break;
                case "ed25519":
                    ClassicalParameters = new Ed25519KeyGenerationParameters(new SecureRandom());
                    break;
                case "ed448":
                    ClassicalParameters = new Ed448KeyGenerationParameters(new SecureRandom());
                    break;
                default:
                    throw new Exception("Classical algorithm not supported");
            }

            switch (PostQuantumName)
            {
                case "mlkem512":
                    PostQuantumParameters = new MLKemKeyGenerationParameters(new Security.SecureRandom(), MLKemParameters.ML_KEM_512);
                    break;
                case "mlkem768":
                    PostQuantumParameters = new MLKemKeyGenerationParameters(new Security.SecureRandom(), MLKemParameters.ML_KEM_768);
                    break;
                case "mlkem1024":
                    PostQuantumParameters = new MLKemKeyGenerationParameters(new Security.SecureRandom(), MLKemParameters.ML_KEM_1024);
                    break;
                case "mldsa44":
                    PostQuantumParameters = new MLDsaKeyGenerationParameters(new Security.SecureRandom(), MLDsaParameters.ML_DSA_44);
                    break;
                case "mldsa65":
                    PostQuantumParameters = new MLDsaKeyGenerationParameters(new Security.SecureRandom(), MLDsaParameters.ML_DSA_65);
                    break;
                case "mldsa87":
                    PostQuantumParameters = new MLDsaKeyGenerationParameters(new Security.SecureRandom(), MLDsaParameters.ML_DSA_87);
                    break;
                case "slhdsasha2128f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_128f_simple);
                    break;
                case "slhdsasha2192f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_192f_simple);
                    break;
                case "slhdsasha2256f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_256f_simple);
                    break;
                case "slhdsasha2128s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_128s_simple);
                    break;
                case "slhdsasha2192s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_192s_simple);
                    break;
                case "slhdsasha2256s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.sha2_256s_simple);
                    break;
                case "slhdsashake128f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_128f_simple);
                    break;
                case "slhdsashake192f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_192f_simple);
                    break;
                case "slhdsashake256f":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_256f_simple);
                    break;
                case "slhdsashake128s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_128s_simple);
                    break;
                case "slhdsashake192s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_192s_simple);
                    break;
                case "slhdsashake256s":
                    PostQuantumParameters = new SphincsPlusKeyGenerationParameters(new Security.SecureRandom(), SphincsPlusParameters.shake_256s_simple);
                    break;
                default:
                    throw new Exception("Post-quantum algorithm not supported");
            }
        }
    }
}
