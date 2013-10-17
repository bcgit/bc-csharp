using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{   
    public class CertificateRequest
    {
        protected ClientCertificateType[] certificateTypes;
        protected IList supportedSignatureAlgorithms;
        protected IList certificateAuthorities;

        /*
         * TODO RFC 5264 7.4.4 A list of the hash/signature algorithm pairs that the server is able to
         * verify, listed in descending order of preference.
         */

        /**
         * @param certificateTypes       see {@link ClientCertificateType} for valid constants.
         * @param certificateAuthorities a {@link Vector} of {@link X500Name}.
         */
        public CertificateRequest(ClientCertificateType[] certificateTypes, IList supportedSignatureAlgorithms, IList certificateAuthorities)
        {
            this.certificateTypes = certificateTypes;
            this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
            this.certificateAuthorities = certificateAuthorities;
        }

        public ClientCertificateType[] CertificateTypes
        {
            get { return certificateTypes; }
        }

        /**
         * @return a {@link Vector} of {@link SignatureAndHashAlgorithm} (or null before TLS 1.2).
         */
        public IList getSupportedSignatureAlgorithms()
        {
            return supportedSignatureAlgorithms;
        }

        public IList CertificateAuthorities
        {
            get { return certificateAuthorities; }
        }

        /**
         * Encode this {@link CertificateRequest} to an {@link OutputStream}.
         *
         * @param output the {@link OutputStream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            if (certificateTypes == null || certificateTypes.Length == 0)
            {
                TlsUtilities.WriteUint8(0, output);
            }
            else
            {
                TlsUtilities.CheckUint8(certificateTypes.Length);
                TlsUtilities.WriteUint8(certificateTypes.Length, output);
                TlsUtilities.WriteUint8Array(certificateTypes, output);
            }

            if (supportedSignatureAlgorithms != null)
            {
                // TODO Check whether SignatureAlgorithm.anonymous is allowed here
                TlsUtilities.EncodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, output);
            }

            if (certificateAuthorities == null || certificateAuthorities.Count == 0)
            {
                TlsUtilities.WriteUint16(0, output);
            }
            else
            {
                var derEncodings = Platform.CreateArrayList(certificateAuthorities.Count);

                int totalLength = 0;
                for (int i = 0; i < certificateAuthorities.Count; ++i)
                {
                    X500Name certificateAuthority = (X500Name)certificateAuthorities[i];
                    byte[] derEncoding = certificateAuthority.GetDerEncoded();
                    derEncodings.Add(derEncoding);
                    totalLength += derEncoding.Length;
                }

                TlsUtilities.CheckUint16(totalLength);
                TlsUtilities.WriteUint16(totalLength, output);

                for (int i = 0; i < derEncodings.Count; ++i)
                {
                    byte[] encDN = (byte[])derEncodings[i];
                    output.Write(encDN, 0, encDN.Length);
                }
            }
        }

        /**
         * Parse a {@link CertificateRequest} from an {@link InputStream}.
         * 
         * @param context
         *            the {@link TlsContext} of the current connection.
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link CertificateRequest} object.
         * @throws IOException
         */
        public static CertificateRequest Parse(TlsContext context, Stream input)
        {
            int numTypes = TlsUtilities.ReadUint8(input);
            ClientCertificateType[] certificateTypes = new ClientCertificateType[numTypes];
            for (int i = 0; i < numTypes; ++i)
            {
                certificateTypes[i] = (ClientCertificateType)TlsUtilities.ReadUint8(input);
            }

            IList supportedSignatureAlgorithms = null;
            if (TlsUtilities.IsTLSv12(context))
            {
                // TODO Check whether SignatureAlgorithm.anonymous is allowed here
                supportedSignatureAlgorithms = TlsUtilities.ParseSupportedSignatureAlgorithms(false, input);
            }

            var certificateAuthorities = Platform.CreateArrayList();
            byte[] certAuthData = TlsUtilities.ReadOpaque16(input);
            MemoryStream bis = new MemoryStream(certAuthData);

            while((bis.Length - bis.Position) > 0)
            {
                byte[] derEncoding = TlsUtilities.ReadOpaque16(bis);
                var asn1 = TlsUtilities.ReadDerObject(derEncoding);
                certificateAuthorities.Add(X500Name.GetInstance(asn1));
            }

            return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
        }
    }
}