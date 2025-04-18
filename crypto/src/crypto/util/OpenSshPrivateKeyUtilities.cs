using System;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Utilities
{
    public static class OpenSshPrivateKeyUtilities
    {
        /// <summary>Magic value for proprietary OpenSSH private key.</summary>
        /// <remarks>C string so null terminated.</remarks>
        private static readonly byte[] AUTH_MAGIC = Encoding.ASCII.GetBytes("openssh-key-v1\0");

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
                throw new ArgumentNullException(nameof(parameters));

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
                    DerInteger.Zero,
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

                SshBuilder builder = new SshBuilder();
                builder.WriteBytes(AUTH_MAGIC);
                builder.WriteStringAscii("none");    // cipher name
                builder.WriteStringAscii("none");    // KDF name
                builder.WriteStringAscii("");        // KDF options

                builder.U32(1); // Number of keys

                {
                    byte[] pkEncoded = OpenSshPublicKeyUtilities.EncodePublicKey(publicKeyParameters);
                    builder.WriteBlock(pkEncoded);
                }

                {
                    SshBuilder pkBuild = new SshBuilder();

                    int checkint = CryptoServicesRegistrar.GetSecureRandom().NextInt();
                    pkBuild.U32((uint)checkint);
                    pkBuild.U32((uint)checkint);

                    pkBuild.WriteStringAscii("ssh-ed25519");

                    // Public key (as part of private key pair)
                    byte[] pubKeyEncoded = publicKeyParameters.GetEncoded();
                    pkBuild.WriteBlock(pubKeyEncoded);

                    // The private key in SSH is 64 bytes long and is the concatenation of the private and the public keys
                    pkBuild.WriteBlock(Arrays.Concatenate(ed25519PrivateKey.GetEncoded(), pubKeyEncoded));

                    // Comment for this private key (empty)
                    pkBuild.WriteStringUtf8("");

                    builder.WriteBlock(pkBuild.GetPaddedBytes());
                }

                return builder.GetBytes();
            }

            throw new ArgumentException("unable to convert " + Platform.GetTypeName(parameters) + " to openssh private key");
        }

        /**
         * Parse a private key.
         * <p/>
         * This method accepts the body of the OpenSSH private key.
         * The easiest way to extract the body is to use PemReader, for example:
         * <p/>
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
                        X962Parameters parameters = X962Parameters.GetInstance(ecPrivateKey.Parameters);
                        ECDomainParameters domainParameters = ECDomainParameters.FromX962Parameters(parameters);
                        result = new ECPrivateKeyParameters("EC", ecPrivateKey.GetKey(), domainParameters);
                    }
                }
            }
            else
            {
                SshBuffer kIn = new SshBuffer(AUTH_MAGIC, blob);

                string cipherName = kIn.ReadStringAscii();
                if (!"none".Equals(cipherName))
                    throw new InvalidOperationException("encrypted keys not supported");

                // KDF name
                kIn.SkipBlock();

                // KDF options
                kIn.SkipBlock();

                int publicKeyCount = kIn.ReadU32();
                if (publicKeyCount != 1)
                    throw new InvalidOperationException("multiple keys not supported");

                // Burn off public key.
                OpenSshPublicKeyUtilities.ParsePublicKey(kIn.ReadBlock());

                byte[] privateKeyBlock = kIn.ReadPaddedBlock();

                if (kIn.HasRemaining())
                    throw new InvalidOperationException("decoded key has trailing data");

                SshBuffer pkIn = new SshBuffer(privateKeyBlock);
                int check1 = pkIn.ReadU32();
                int check2 = pkIn.ReadU32();

                if (check1 != check2)
                    throw new InvalidOperationException("private key check values are not the same");

                string keyType = pkIn.ReadStringAscii();

                if ("ssh-ed25519".Equals(keyType))
                {
                    // Public key
                    pkIn.SkipBlock();

                    // Private key value..
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    ReadOnlySpan<byte> edPrivateKey = pkIn.ReadBlockSpan();
#else
                    byte[] edPrivateKey = pkIn.ReadBlock();
#endif

                    if (edPrivateKey.Length != Ed25519PrivateKeyParameters.KeySize + Ed25519PublicKeyParameters.KeySize)
                        throw new InvalidOperationException("private key value of wrong length");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    result = new Ed25519PrivateKeyParameters(edPrivateKey[..Ed25519PrivateKeyParameters.KeySize]);
#else
                    result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);
#endif
                }
                else if (keyType.StartsWith("ecdsa"))
                {
                    var curveName = pkIn.ReadStringAscii();

                    var oid = SshNamedCurves.GetOid(curveName) ??
                        throw new InvalidOperationException("OID not found for: " + keyType);

                    var x9ECParameters = SshNamedCurves.GetByOid(oid) ??
                        throw new InvalidOperationException("Curve not found for: " + oid);

                    // Skip public key.
                    pkIn.SkipBlock();

                    var d = pkIn.ReadMpintPositive();

                    result = new ECPrivateKeyParameters(d, new ECNamedDomainParameters(oid, x9ECParameters));
                }
                else if (keyType.StartsWith("ssh-rsa"))
                {
                    BigInteger modulus = pkIn.ReadMpintPositive();
                    BigInteger pubExp = pkIn.ReadMpintPositive();
                    BigInteger privExp = pkIn.ReadMpintPositive();
                    BigInteger coef = pkIn.ReadMpintPositive();
                    BigInteger p = pkIn.ReadMpintPositive();
                    BigInteger q = pkIn.ReadMpintPositive();

                    BigInteger pSub1 = p.Subtract(BigIntegers.One);
                    BigInteger qSub1 = q.Subtract(BigIntegers.One);
                    BigInteger dP = privExp.Remainder(pSub1);
                    BigInteger dQ = privExp.Remainder(qSub1);

                    result = new RsaPrivateCrtKeyParameters(modulus, pubExp, privExp, p, q, dP, dQ, coef);
                }

                // Comment for private key
                pkIn.SkipBlock();

                if (pkIn.HasRemaining())
                    throw new ArgumentException("private key block has trailing data");
            }

            return result ?? throw new ArgumentException("unable to parse key"); ;
        }

        /**
         * AllIntegers returns true if the sequence holds only DerInteger types.
         **/
        private static bool AllIntegers(Asn1Sequence sequence)
        {
            for (int t = 0; t < sequence.Count; t++)
            {
                if (!(sequence[t] is DerInteger))
                    return false;
            }
            return true;
        }
    }
}
