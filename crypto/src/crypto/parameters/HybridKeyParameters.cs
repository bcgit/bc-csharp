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
                if(!HybridParameters.HybridNameToOid.TryGetValue(CanonicalName, out objectId))
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
