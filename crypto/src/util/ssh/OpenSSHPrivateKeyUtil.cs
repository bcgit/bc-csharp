using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;

namespace Org.BouncyCastle.Utilities.SSH
{
    public class OpenSSHPrivateKeyUtil
    {
        private OpenSSHPrivateKeyUtil()
        {

        }

        /**
         * Magic value for proprietary OpenSSH private key.
         **/
        static readonly byte[] AUTH_MAGIC = Strings.ToByteArray("openssh-key-v1\0"); // C string so null terminated

        /**
         * Encode a cipher parameters into an OpenSSH private key.
         * This does not add headers like ----BEGIN RSA PRIVATE KEY----
         *
         * @param parameters the cipher parameters.
         * @return a byte array
         */
        public static byte[] EncodePrivateKey(AsymmetricKeyParameter parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentException("parameters is null");
            }

            if (parameters is RsaPrivateCrtKeyParameters || parameters is ECPrivateKeyParameters)
            {
                PrivateKeyInfo pInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(parameters);
                return pInfo.ParsePrivateKey().GetEncoded();
            }
            else if (parameters is DsaPrivateKeyParameters dsaPrivateKey)
            {
                DsaParameters dsaparameters = dsaPrivateKey.Parameters;

                Asn1EncodableVector vec = new Asn1EncodableVector
                {
                    new DerInteger(0),
                    new DerInteger(dsaparameters.P),
                    new DerInteger(dsaparameters.Q),
                    new DerInteger(dsaparameters.G)
                };

                // public key = g.modPow(x, p);
                BigInteger pubKey = dsaparameters.P.ModPow(dsaPrivateKey.X, dsaparameters.P);
                vec.Add(new DerInteger(pubKey));
                vec.Add(new DerInteger(dsaPrivateKey.X));
                try
                {
                    return new DerSequence(vec).GetEncoded();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("unable to encode DSAPrivateKeyParameters " + ex.Message);
                }
            }
            else if (parameters is Ed25519PrivateKeyParameters ed25519PrivateKey)
            {
                Ed25519PublicKeyParameters publicKeyParameters = ed25519PrivateKey.GeneratePublicKey();

                SSHBuilder builder = new SSHBuilder();
                builder.WriteBytes(AUTH_MAGIC);
                builder.WriteString("none");    // cipher name
                builder.WriteString("none");    // KDF name
                builder.WriteString("");        // KDF options

                builder.U32(1); // Number of keys

                {
                    byte[] pkEncoded = OpenSSHPublicKeyUtil.EncodePublicKey(publicKeyParameters);
                    builder.WriteBlock(pkEncoded);
                }

                {
                    SSHBuilder pkBuild = new SSHBuilder();

                    int checkint = CryptoServicesRegistrar.GetSecureRandom().NextInt();
                    pkBuild.U32((uint)checkint);
                    pkBuild.U32((uint)checkint);

                    pkBuild.WriteString("ssh-ed25519");

                    // Public key (as part of private key pair)
                    byte[] pubKeyEncoded = publicKeyParameters.GetEncoded();
                    pkBuild.WriteBlock(pubKeyEncoded);

                    // The private key in SSH is 64 bytes long and is the concatenation of the private and the public keys
                    pkBuild.WriteBlock(Arrays.Concatenate(ed25519PrivateKey.GetEncoded(), pubKeyEncoded));

                    // Comment for this private key (empty)
                    pkBuild.WriteString("");    

                    builder.WriteBlock(pkBuild.GetPaddedBytes());
                }

                return builder.GetBytes();
            }

            throw new ArgumentException("unable to convert " + parameters.GetType().Name + " to openssh private key");

        }

        /**
         * Parse a private key.
         * <p>
         * This method accepts the body of the OpenSSH private key.
         * The easiest way to extract the body is to use PemReader, for example:
         * <p>
         * byte[] blob = new PemReader([reader]).readPemObject().getContent();
         * CipherParameters params = parsePrivateKeyBlob(blob);
         *
         * @param blob The key.
         * @return A cipher parameters instance.
         */
        public static AsymmetricKeyParameter ParsePrivateKeyBlob(byte[] blob)
        {
            AsymmetricKeyParameter result = null;

            if (blob[0] == 0x30)
            {
                Asn1Sequence sequence = Asn1Sequence.GetInstance(blob);

                if (sequence.Count == 6)
                {
                    if (AllIntegers(sequence) && ((DerInteger)sequence[0]).PositiveValue.Equals(BigIntegers.Zero))
                    {
                        // length of 6 and all Integers -- DSA
                        result = new DsaPrivateKeyParameters(
                            ((DerInteger)sequence[5]).PositiveValue,
                            new DsaParameters(
                                ((DerInteger)sequence[1]).PositiveValue,
                                ((DerInteger)sequence[2]).PositiveValue,
                                ((DerInteger)sequence[3]).PositiveValue)
                        );
                    }
                }
                else if (sequence.Count == 9)
                {
                    if (AllIntegers(sequence) && ((DerInteger)sequence[0]).PositiveValue.Equals(BigIntegers.Zero))
                    {
                        // length of 8 and all Integers -- RSA
                        RsaPrivateKeyStructure rsaPrivateKey = RsaPrivateKeyStructure.GetInstance(sequence);

                        result = new RsaPrivateCrtKeyParameters(
                            rsaPrivateKey.Modulus,
                            rsaPrivateKey.PublicExponent,
                            rsaPrivateKey.PrivateExponent,
                            rsaPrivateKey.Prime1,
                            rsaPrivateKey.Prime2,
                            rsaPrivateKey.Exponent1,
                            rsaPrivateKey.Exponent2,
                            rsaPrivateKey.Coefficient);
                    }
                }
                else if (sequence.Count == 4)
                {
                    if (sequence[3] is Asn1TaggedObject && sequence[2] is Asn1TaggedObject)
                    {
                        ECPrivateKeyStructure ecPrivateKey = ECPrivateKeyStructure.GetInstance(sequence);
                        DerObjectIdentifier curveOID = DerObjectIdentifier.GetInstance(ecPrivateKey.GetParameters());
                        X9ECParameters x9Params = ECNamedCurveTable.GetByOid(curveOID);
                        result = new ECPrivateKeyParameters(
                            ecPrivateKey.GetKey(),
                            new ECNamedDomainParameters(
                                curveOID,
                                x9Params));
                    }
                }
            }
            else
            {
                SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);

                String cipherName = kIn.ReadString();
                if (!"none".Equals(cipherName))
                {
                    throw new InvalidOperationException("encrypted keys not supported");
                }

                // KDF name
                kIn.SkipBlock();

                // KDF options
                kIn.SkipBlock();

                int publicKeyCount = kIn.ReadU32();
                if (publicKeyCount != 1)
                {
                    throw new InvalidOperationException("multiple keys not supported");
                }

                // Burn off public key.
                OpenSSHPublicKeyUtil.ParsePublicKey(kIn.ReadBlock());

                byte[] privateKeyBlock = kIn.ReadPaddedBlock();

                if (kIn.HasRemaining())
                {
                    throw new InvalidOperationException("decoded key has trailing data");
                }

                SSHBuffer pkIn = new SSHBuffer(privateKeyBlock);
                int check1 = pkIn.ReadU32();
                int check2 = pkIn.ReadU32();

                if (check1 != check2)
                {
                    throw new InvalidOperationException("private key check values are not the same");
                }

                String keyType = pkIn.ReadString();

                if ("ssh-ed25519".Equals(keyType))
                {
                    // Public key
                    pkIn.ReadBlock();
                    // Private key value..
                    byte[] edPrivateKey = pkIn.ReadBlock();
                    if (edPrivateKey.Length != Ed25519PrivateKeyParameters.KeySize + Ed25519PublicKeyParameters.KeySize)
                    {
                        throw new InvalidOperationException("private key value of wrong length");
                    }

                    result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);
                }
                else if (keyType.StartsWith("ecdsa"))
                {
                    DerObjectIdentifier oid = SSHNamedCurves.GetByName(Strings.FromByteArray(pkIn.ReadBlock())) ?? 
                        throw new InvalidOperationException("OID not found for: " + keyType);
                    X9ECParameters curveParams = NistNamedCurves.GetByOid(oid) ?? throw new InvalidOperationException("Curve not found for: " + oid);

                    // Skip public key.
                    pkIn.ReadBlock();
                    byte[] privKey = pkIn.ReadBlock();

                    result = new ECPrivateKeyParameters(new BigInteger(1, privKey),
                        new ECNamedDomainParameters(oid, curveParams));
                }
                else if (keyType.StartsWith("ssh-rsa"))
                {
                    BigInteger modulus = new BigInteger(1, pkIn.ReadBlock());
                    BigInteger pubExp = new BigInteger(1, pkIn.ReadBlock());
                    BigInteger privExp = new BigInteger(1, pkIn.ReadBlock());
                    BigInteger coef = new BigInteger(1, pkIn.ReadBlock());
                    BigInteger p = new BigInteger(1, pkIn.ReadBlock());
                    BigInteger q = new BigInteger(1, pkIn.ReadBlock());

                    BigInteger pSub1 = p.Subtract(BigIntegers.One);
                    BigInteger qSub1 = q.Subtract(BigIntegers.One);
                    BigInteger dP = privExp.Remainder(pSub1);
                    BigInteger dQ = privExp.Remainder(qSub1);

                    result = new RsaPrivateCrtKeyParameters(
                                    modulus,
                                    pubExp,
                                    privExp,
                                    p,
                                    q,
                                    dP,
                                    dQ,
                                    coef);
                }

                // Comment for private key
                pkIn.SkipBlock();

                if (pkIn.HasRemaining())
                {
                    throw new ArgumentException("private key block has trailing data");
                }
            }

            if (result == null)
            {
                throw new ArgumentException("unable to parse key");
            }

            return result;
        }

        /**
         * allIntegers returns true if the sequence holds only DerInteger types.
         **/
        private static Boolean AllIntegers(Asn1Sequence sequence)
        {
            for (int t = 0; t < sequence.Count; t++)
            {
                if (!(sequence[t] is DerInteger))
            {
                return false;
            }
        }
        return true;
    }
}
}
