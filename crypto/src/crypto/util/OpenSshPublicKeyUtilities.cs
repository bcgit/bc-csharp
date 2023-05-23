using System;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Utilities
{
    public static class OpenSshPublicKeyUtilities
    {
        private static readonly string RSA = "ssh-rsa";
        private static readonly string ECDSA = "ecdsa";
        private static readonly string ED_25519 = "ssh-ed25519";
        private static readonly string DSS = "ssh-dss";

        /**
         * Parse a public key.
         * <p/>
         * This method accepts the bytes that are Base64 encoded in an OpenSSH public key file.
         *
         * @param encoded The key.
         * @return An AsymmetricKeyParameter instance.
         */
        public static AsymmetricKeyParameter ParsePublicKey(byte[] encoded)
        {
            SshBuffer buffer = new SshBuffer(encoded);
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
                throw new ArgumentNullException(nameof(cipherParameters));
            if (cipherParameters.IsPrivate)
                throw new ArgumentException("Not a public key", nameof(cipherParameters));
            if (cipherParameters is RsaKeyParameters rsaPubKey)
            {
                SshBuilder builder = new SshBuilder();
                builder.WriteStringAscii(RSA);
                builder.WriteMpint(rsaPubKey.Exponent);
                builder.WriteMpint(rsaPubKey.Modulus);
                return builder.GetBytes();
            }
            else if (cipherParameters is ECPublicKeyParameters ecPublicKey)
            {
                string curveName = null;
                var oid = ecPublicKey.PublicKeyParamSet;
                if (oid != null)
                {
                    curveName = SshNamedCurves.GetName(oid);
                }
                if (curveName == null)
                    throw new ArgumentException("unable to derive ssh curve name for EC public key");

                SshBuilder builder = new SshBuilder();
                builder.WriteStringAscii(ECDSA + "-sha2-" + curveName); // Magic
                builder.WriteStringAscii(curveName);
                builder.WriteBlock(ecPublicKey.Q.GetEncoded(false)); //Uncompressed
                return builder.GetBytes();
            }
            else if (cipherParameters is DsaPublicKeyParameters dsaPubKey)
            {
                DsaParameters dsaParams = dsaPubKey.Parameters;

                SshBuilder builder = new SshBuilder();
                builder.WriteStringAscii(DSS);
                builder.WriteMpint(dsaParams.P);
                builder.WriteMpint(dsaParams.Q);
                builder.WriteMpint(dsaParams.G);
                builder.WriteMpint(dsaPubKey.Y);
                return builder.GetBytes();
            }
            else if (cipherParameters is Ed25519PublicKeyParameters ed25519PublicKey)
            {
                SshBuilder builder = new SshBuilder();
                builder.WriteStringAscii(ED_25519);
                builder.WriteBlock(ed25519PublicKey.GetEncoded());
                return builder.GetBytes();
            }

            throw new ArgumentException("unable to convert " + Platform.GetTypeName(cipherParameters) + " to public key");
        }

        /**
         * Format a public key from an AsymmetricKeyParameter instance to OpenSSH public key format.
         *
         * @param cipherParameters The key to encode.
         * @param comments The comments of the public key.
         * @return the key OpenSSH formatted.
         * @throws IOException
         */
        public static string FormatPublicKey(AsymmetricKeyParameter cipherParameters, string comments)
        {
            if (cipherParameters == null)
                throw new ArgumentNullException(nameof(cipherParameters));
            if (cipherParameters.IsPrivate)
                throw new ArgumentException("Not a public key", nameof(cipherParameters));

            if (cipherParameters is RsaKeyParameters rsaPubKey)
            {
                SshBuilder builder = new SshBuilder();
                builder.WriteMpint(rsaPubKey.Exponent);
                builder.WriteMpint(rsaPubKey.Modulus);
                return $"{RSA} {Base64.ToBase64String(builder.GetBytes())} {comments}";
            }
            else if (cipherParameters is ECPublicKeyParameters ecPublicKey)
            {
                string curveName = null;

                var oid = ecPublicKey.PublicKeyParamSet;
                if (oid != null)
                {
                    curveName = SshNamedCurves.GetName(oid);
                }

                if (curveName == null)
                    throw new ArgumentException("unable to derive ssh curve name for EC public key");

                SshBuilder builder = new SshBuilder();
                builder.WriteStringAscii(curveName);
                builder.WriteBlock(ecPublicKey.Q.GetEncoded(false)); //Uncompressed
                return $"{ECDSA}-sha2-{curveName} {Base64.ToBase64String(builder.GetBytes())} {comments}";
            }
            else if (cipherParameters is DsaPublicKeyParameters dsaPubKey)
            {
                DsaParameters dsaParams = dsaPubKey.Parameters;

                SshBuilder builder = new SshBuilder();
                builder.WriteMpint(dsaParams.P);
                builder.WriteMpint(dsaParams.Q);
                builder.WriteMpint(dsaParams.G);
                builder.WriteMpint(dsaPubKey.Y);
                return $"{DSS} {Base64.ToBase64String(builder.GetBytes())} {comments}";
            }
            else if (cipherParameters is Ed25519PublicKeyParameters ed25519PublicKey)
            {
                SshBuilder builder = new SshBuilder();
                builder.WriteBlock(ed25519PublicKey.GetEncoded());
                return $"{ED_25519} {Base64.ToBase64String(builder.GetBytes())} {comments}";
            }

            throw new ArgumentException("unable to convert " + Platform.GetTypeName(cipherParameters) + " to public key");
        }

        /**
         * Parse a public key from an SSHBuffer instance.
         *
         * @param buffer containing the SSH public key.
         * @return A CipherParameters instance.
         */
        private static AsymmetricKeyParameter ParsePublicKey(SshBuffer buffer)
        {
            AsymmetricKeyParameter result = null;

            string magic = buffer.ReadStringAscii();
            if (RSA.Equals(magic))
            {
                BigInteger e = buffer.ReadMpintPositive();
                BigInteger n = buffer.ReadMpintPositive();
                result = new RsaKeyParameters(false, n, e);
            }
            else if (DSS.Equals(magic))
            {
                BigInteger p = buffer.ReadMpintPositive();
                BigInteger q = buffer.ReadMpintPositive();
                BigInteger g = buffer.ReadMpintPositive();
                BigInteger pubKey = buffer.ReadMpintPositive();

                result = new DsaPublicKeyParameters(pubKey, new DsaParameters(p, q, g));
            }
            else if (magic.StartsWith(ECDSA))
            {
                var curveName = buffer.ReadStringAscii();

                var oid = SshNamedCurves.GetOid(curveName);

                X9ECParameters x9ECParameters = oid == null ? null : SshNamedCurves.GetByOid(oid);
                if (x9ECParameters == null)
                {
                    throw new InvalidOperationException(
                        "unable to find curve for " + magic + " using curve name " + curveName);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ReadOnlySpan<byte> pointEncoding = buffer.ReadBlockSpan();
#else
                byte[] pointEncoding = buffer.ReadBlock();
#endif
                var point = x9ECParameters.Curve.DecodePoint(pointEncoding);

                result = new ECPublicKeyParameters(point, new ECNamedDomainParameters(oid, x9ECParameters));
            }
            else if (ED_25519.Equals(magic))
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ReadOnlySpan<byte> pubKeyBytes = buffer.ReadBlockSpan();
#else
                byte[] pubKeyBytes = buffer.ReadBlock();
#endif

                result = new Ed25519PublicKeyParameters(pubKeyBytes);
            }

            if (result == null)
                throw new ArgumentException("unable to parse key");

            if (buffer.HasRemaining())
                throw new ArgumentException("decoded key has trailing data");

            return result;
        }
    }
}
