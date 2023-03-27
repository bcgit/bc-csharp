using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities.SSH
{
    public class OpenSSHPublicKeyUtil
    {
        private OpenSSHPublicKeyUtil()
        {

        }

        private static readonly String RSA = "ssh-rsa";
        private static readonly String ECDSA = "ecdsa";
        private static readonly String ED_25519 = "ssh-ed25519";
        private static readonly String DSS = "ssh-dss";

        /**
         * Parse a public key.
         * <p>
         * This method accepts the bytes that are Base64 encoded in an OpenSSH public key file.
         *
         * @param encoded The key.
         * @return An AsymmetricKeyParameter instance.
         */
        public static AsymmetricKeyParameter ParsePublicKey(byte[] encoded)
        {
            SSHBuffer buffer = new SSHBuffer(encoded);
            return ParsePublicKey(buffer);
        }

        /**
         * Encode a public key from an AsymmetricKeyParameter instance.
         *
         * @param cipherParameters The key to encode.
         * @return the key OpenSSH encoded.
         * @throws IOException
         */
        public static byte[] EncodePublicKey(AsymmetricKeyParameter cipherParameters)
        {
            if (cipherParameters == null)
            {
                throw new ArgumentException("cipherParameters was null.");
            }

            if (cipherParameters is RsaKeyParameters)
            {
                if (cipherParameters.IsPrivate)
                {
                    throw new ArgumentException("RSAKeyParamaters was for encryption");
                }

                RsaKeyParameters rsaPubKey = (RsaKeyParameters)cipherParameters;

                SSHBuilder builder = new SSHBuilder();
                builder.WriteString(RSA);
                builder.WriteBigNum(rsaPubKey.Exponent);
                builder.WriteBigNum(rsaPubKey.Modulus);

                return builder.GetBytes();

            }
            else if (cipherParameters is ECPublicKeyParameters ecPublicKey)
            {
                SSHBuilder builder = new SSHBuilder();

                //
                // checked for named curve parameters..
                //
                String name = SSHNamedCurves.GetNameForParameters(ecPublicKey.Parameters);

                if (name == null)
                {
                    throw new ArgumentException("unable to derive ssh curve name for " + ecPublicKey.Parameters.Curve.GetType().Name);
                }

                builder.WriteString(ECDSA + "-sha2-" + name); // Magic
                builder.WriteString(name);
                builder.WriteBlock(ecPublicKey.Q.GetEncoded(false)); //Uncompressed
                return builder.GetBytes();
            }
            else if (cipherParameters is DsaPublicKeyParameters dsaPubKey)
            {
                DsaParameters dsaParams = dsaPubKey.Parameters;

                SSHBuilder builder = new SSHBuilder();
                builder.WriteString(DSS);
                builder.WriteBigNum(dsaParams.P);
                builder.WriteBigNum(dsaParams.Q);
                builder.WriteBigNum(dsaParams.G);
                builder.WriteBigNum(dsaPubKey.Y);
                return builder.GetBytes();
            }
            else if (cipherParameters is Ed25519PublicKeyParameters ed25519PublicKey)
            {
                SSHBuilder builder = new SSHBuilder();
                builder.WriteString(ED_25519);
                builder.WriteBlock(ed25519PublicKey.GetEncoded());
                return builder.GetBytes();
            }

            throw new ArgumentException("unable to convert " + cipherParameters.GetType().Name + " to private key");
        }

        /**
         * Parse a public key from an SSHBuffer instance.
         *
         * @param buffer containing the SSH public key.
         * @return A CipherParameters instance.
         */
        public static AsymmetricKeyParameter ParsePublicKey(SSHBuffer buffer)
        {
            AsymmetricKeyParameter result = null;

            string magic = buffer.ReadString();
            if (RSA.Equals(magic))
            {
                BigInteger e = buffer.ReadBigNumPositive();
                BigInteger n = buffer.ReadBigNumPositive();
                result = new RsaKeyParameters(false, n, e);
            }
            else if (DSS.Equals(magic))
            {
                BigInteger p = buffer.ReadBigNumPositive();
                BigInteger q = buffer.ReadBigNumPositive();
                BigInteger g = buffer.ReadBigNumPositive();
                BigInteger pubKey = buffer.ReadBigNumPositive();

                result = new DsaPublicKeyParameters(pubKey, new DsaParameters(p, q, g));
            }
            else if (magic.StartsWith(ECDSA))
            {
                String curveName = buffer.ReadString();
                DerObjectIdentifier oid = SSHNamedCurves.GetByName(curveName);
                X9ECParameters x9ECParameters = SSHNamedCurves.GetParameters(oid) ?? 
                    throw new InvalidOperationException("unable to find curve for " + magic + " using curve name " + curveName);
                var curve = x9ECParameters.Curve;
                byte[] pointRaw = buffer.ReadBlock();

                result = new ECPublicKeyParameters(
                    curve.DecodePoint(pointRaw),
                    new ECNamedDomainParameters(oid, x9ECParameters));
            }
            else if (ED_25519.Equals(magic))
            {
                byte[] pubKeyBytes = buffer.ReadBlock();
                if (pubKeyBytes.Length != Ed25519PublicKeyParameters.KeySize)
                {
                    throw new InvalidOperationException("public key value of wrong length");
                }

                result = new Ed25519PublicKeyParameters(pubKeyBytes, 0);
            }

            if (result == null)
            {
                throw new ArgumentException("unable to parse key");
            }

            if (buffer.HasRemaining())
            {
                throw new ArgumentException("decoded key has trailing data");
            }

            return result;
        }
    }
}
