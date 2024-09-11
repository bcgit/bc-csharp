using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.MLKem;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.crypto.parameters
{
    public class HybridKeyParameters
        : AsymmetricKeyParameter
    {
        public static readonly Dictionary<string, string> HybridNameToOid = new Dictionary<string, string>()
        {
            { "p256_mlkem512" , "1.3.6.1.4.1.22554.5.7.1" },
            { "x25519_mlkem512" , "1.3.6.1.4.1.22554.5.8.1" },
            { "p384_mlkem768" , "1.3.9999.99.75" },
            { "x448_mlkem768" , "1.3.9999.99.53" },
            { "x25519_mlkem768" , "1.3.9999.99.54" },
            { "p256_mlkem768" , "1.3.9999.99.55" },
            { "p521_mlkem1024" , "1.3.9999.99.76" },
            { "p384_mlkem1024" , "1.3.6.1.4.1.42235.6" },
            { "p256_dilithium2" , "1.3.9999.2.7.1" },
            //{ "rsa3072_dilithium2" , "1.3.9999.2.7.2" },
            { "p384_dilithium3" , "1.3.9999.2.7.3" },
            { "p521_dilithium5" , "1.3.9999.2.7.4" },
            //{ "rsa3072_mldsa44" , "1.3.9999.7.2" },
            //{ "mldsa44_rsa2048" , "2.16.840.1.114027.80.8.1.2" },
            { "ed25519_mldsa44" , "2.16.840.1.114027.80.8.1.3" },
            { "p256_mldsa44" , "2.16.840.1.114027.80.8.1.4" },
            { "p384_mldsa65" , "1.3.9999.7.3" },
            //{ "mldsa65_rsa3072" , "2.16.840.1.114027.80.8.1.7" },
            { "p256_mldsa65" , "2.16.840.1.114027.80.8.1.8" },
            { "ed25519_mldsa65" , "2.16.840.1.114027.80.8.1.10" },
            { "p521_mldsa87" , "1.3.9999.7.4" },
            { "p384_mldsa87" , "2.16.840.1.114027.80.8.1.11" },
            { "ed448_mldsa87" , "2.16.840.1.114027.80.8.1.13" },
            { "p256_slhdsasha2128f" , "1.3.9999.6.4.14" },
            //{ "rsa3072_slhdsasha2128f" , "1.3.9999.6.4.15" },
            { "p256_slhdsasha2128s" , "1.3.9999.6.4.17" },
            //{ "rsa3072_slhdsasha2128s" , "1.3.9999.6.4.18" },
            { "p384_slhdsasha2192f" , "1.3.9999.6.5.11" },
            { "p384_slhdsasha2192s" , "1.3.9999.6.5.13" },
            { "p521_slhdsasha2256f" , "1.3.9999.6.6.11" },
            { "p521_slhdsasha2256s" , "1.3.9999.6.6.13" },
            { "p256_slhdsashake128f" , "1.3.9999.6.7.14" },
            //{ "rsa3072_slhdsashake128f" , "1.3.9999.6.7.15" },
            { "p256_slhdsashake128s" , "1.3.9999.6.7.17" },
            //{ "rsa3072_slhdsashake128s" , "1.3.9999.6.7.18" },
            { "p384_slhdsashake192f" , "1.3.9999.6.8.11" },
            { "p384_slhdsashake192s" , "1.3.9999.6.8.13" },
            { "p521_slhdsashake256f" , "1.3.9999.6.9.11" },
            { "p521_slhdsashake256s" , "1.3.9999.6.9.13" },
        };

        public static readonly Dictionary<string, string> HybridOidToName = new Dictionary<string, string>()
        {
            { "1.3.6.1.4.1.22554.5.7.1" , "p256_mlkem512" },
            { "1.3.6.1.4.1.22554.5.8.1" , "x25519_mlkem512" },
            { "1.3.9999.99.75" , "p384_mlkem768" },
            { "1.3.9999.99.53" , "x448_mlkem768" },
            { "1.3.9999.99.54" , "x25519_mlkem768" },
            { "1.3.9999.99.55" , "p256_mlkem768" },
            { "1.3.9999.99.76" , "p521_mlkem1024" },
            { "1.3.6.1.4.1.42235.6" , "p384_mlkem1024" },
            { "1.3.9999.2.7.1" , "p256_dilithium2" },
            //{ "1.3.9999.2.7.2" , "rsa3072_dilithium2" },
            { "1.3.9999.2.7.3" , "p384_dilithium3" },
            { "1.3.9999.2.7.4" , "p521_dilithium5" },
            //{ "1.3.9999.7.2" , "rsa3072_mldsa44" },
            //{ "2.16.840.1.114027.80.8.1.2" , "mldsa44_rsa2048" },
            { "2.16.840.1.114027.80.8.1.3" , "ed25519_mldsa44" },
            { "2.16.840.1.114027.80.8.1.4" , "p256_mldsa44" },
            { "1.3.9999.7.3" , "p384_mldsa65" },
            //{ "2.16.840.1.114027.80.8.1.7" , "mldsa65_rsa3072" },
            { "2.16.840.1.114027.80.8.1.8" , "p256_mldsa65" },
            { "2.16.840.1.114027.80.8.1.10" , "ed25519_mldsa65" },
            { "1.3.9999.7.4" , "p521_mldsa87" },
            { "2.16.840.1.114027.80.8.1.11" , "p384_mldsa87" },
            { "2.16.840.1.114027.80.8.1.13" , "ed448_mldsa87" },
            { "1.3.9999.6.4.14" , "p256_slhdsasha2128f" },
            //{ "1.3.9999.6.4.15" , "rsa3072_slhdsasha2128f" },
            { "1.3.9999.6.4.17" , "p256_slhdsasha2128s" },
            //{ "1.3.9999.6.4.18" , "rsa3072_slhdsasha2128s" },
            { "1.3.9999.6.5.11" , "p384_slhdsasha2192f" },
            { "1.3.9999.6.5.13" , "p384_slhdsasha2192s" },
            { "1.3.9999.6.6.11" , "p521_slhdsasha2256f" },
            { "1.3.9999.6.6.13" , "p521_slhdsasha2256s" },
            { "1.3.9999.6.7.14" , "p256_slhdsashake128f" },
            //{ "1.3.9999.6.7.15" , "rsa3072_slhdsashake128f" },
            { "1.3.9999.6.7.17" , "p256_slhdsashake128s" },
            //{ "1.3.9999.6.7.18" , "rsa3072_slhdsashake128s" },
            { "1.3.9999.6.8.11" , "p384_slhdsashake192f" },
            { "1.3.9999.6.8.13" , "p384_slhdsashake192s" },
            { "1.3.9999.6.9.11" , "p521_slhdsashake256f" },
            { "1.3.9999.6.9.13" , "p521_slhdsashake256s" },
        };

        public readonly DerObjectIdentifier AlgorithmOid;

        public AsymmetricKeyParameter Classical {  get; private set; }

        public AsymmetricKeyParameter PostQuantum {  get; private set; }

        public string CanonicalName { get; private set; }

        public HybridKeyParameters(AsymmetricKeyParameter classical, AsymmetricKeyParameter postQuantum, DerObjectIdentifier oid = null)
            : base(classical.IsPrivate)
        {
            if (classical.IsPrivate != postQuantum.IsPrivate)
                throw new ArgumentException("Mixed private and public keys");

            Classical = classical;
            PostQuantum = postQuantum;
            AlgorithmOid = null;

            if (oid != null)
            {
                AlgorithmOid = oid;
                CanonicalName = null;
                return;
            }

            string classicalCanonicalName = null;

            //if (Classical is RsaKeyParameters)
            //{
                //classicalCanonicalName = string.Concat("rsa", (Classical as RsaKeyParameters).Modulus.BitLength);
            //}
            if (Classical is ECKeyParameters)
            {
                var curve = (Classical as ECKeyParameters).Parameters.Curve;

                if (curve is SecP256R1Curve)
                {
                    classicalCanonicalName = "p256";
                }
                else if (curve is SecP384R1Curve)
                {
                    classicalCanonicalName = "p384";
                }
                else if (curve is SecP521R1Curve)
                {
                    classicalCanonicalName = "p521";
                }
            }
            else if (Classical is X25519PrivateKeyParameters || Classical is X25519PublicKeyParameters)
            {
                classicalCanonicalName = "x25519";
            }
            else if (Classical is Ed25519PrivateKeyParameters || Classical is Ed25519PublicKeyParameters)
            {
                classicalCanonicalName = "ed25519";
            }
            else if (Classical is X448PrivateKeyParameters || Classical is X448PublicKeyParameters)
            {
                classicalCanonicalName = "x448";
            }
            else if (Classical is Ed448PrivateKeyParameters || Classical is Ed448PrivateKeyParameters)
            {
                classicalCanonicalName = "ed448";
            }

            string postQuantumCanonicalName = null;

            if (PostQuantum is MLKemKeyParameters)
            {
                var name = (PostQuantum as MLKemKeyParameters).Parameters.Name;
                switch (name)
                {
                    case "ML-KEM-512":
                        postQuantumCanonicalName = "mlkem512";
                        break;
                    case "ML-KEM-768":
                        postQuantumCanonicalName = "mlkem768";
                        break;
                    case "ML-KEM-1024":
                        postQuantumCanonicalName = "mlkem1024";
                        break;
                }
            }
            else if (PostQuantum is DilithiumKeyParameters)
            {
                switch ((PostQuantum as DilithiumKeyParameters).Parameters.GetEngine(null).Mode)
                {
                    case 2:
                        postQuantumCanonicalName = string.Concat("mldsa", $"{44}");
                        break;
                    case 3:
                        postQuantumCanonicalName = string.Concat("mldsa", $"{65}");
                        break;
                    case 5:
                        postQuantumCanonicalName = string.Concat("mldsa", $"{87}");
                        break;
                }
            }
            else if (PostQuantum is SphincsPlusKeyParameters)
            {
                postQuantumCanonicalName = String.Concat("slhdsa", (PostQuantum as SphincsPlusKeyParameters).Parameters.Name.Replace("-", "").Replace("simple", ""));
            }

            if (postQuantumCanonicalName != null && classicalCanonicalName != null)
            {
                CanonicalName = string.Concat(classicalCanonicalName, "_", postQuantumCanonicalName);
            }
            else
            {
                throw new Exception("Unsupported hybrid combination");
            }

            string objectId = null;
            if (CanonicalName != null)
            {
                if(!HybridNameToOid.TryGetValue(CanonicalName, out objectId))
                {
                    throw new Exception($"Object identifier for {CanonicalName} not found");
                }
            }

            AlgorithmOid = new DerObjectIdentifier(objectId);
        }

        public override bool Equals(object obj)
        {
            return (this == obj) ||
                (obj is HybridKeyParameters other && IsPrivate == other.IsPrivate &&
                Classical.Equals(other.Classical) && PostQuantum.Equals(other.PostQuantum));
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 23 + Classical.GetHashCode();
            hash = hash * 23 + PostQuantum.GetHashCode();
            return hash;
        }
    }
}
