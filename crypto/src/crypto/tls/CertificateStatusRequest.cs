using System;
using System.IO;


namespace Org.BouncyCastle.Crypto.Tls
{

    public class CertificateStatusRequest
    {
        private CertificateStatusType statusType;
        protected Object request;

        public CertificateStatusRequest(short statusType, Object request)
        {
            if (!isCorrectType(statusType, request))
            {
                throw new ArgumentException("'request' is not an instance of the correct type");
            }

            this.statusType = (CertificateStatusType)statusType;
            this.request = request;
        }

        public CertificateStatusType StatusType
        {
            get
            {
                return statusType;
            }
        }

        public Object Request
        {
            get
            {
                return request;
            }
        }

        public OCSPStatusRequest getOCSPStatusRequest()
        {
            if (!isCorrectType((short)CertificateStatusType.ocsp, request))
            {
                throw new InvalidOperationException("'request' is not an OCSPStatusRequest");
            }
            return (OCSPStatusRequest)request;
        }

        /**
         * Encode this {@link CertificateStatusRequest} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void encode(Stream output)
        {
            TlsUtilities.WriteUint8((byte)statusType, output);

            switch (statusType)
            {
                case CertificateStatusType.ocsp:
                    ((OCSPStatusRequest)request).Encode(output);
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /**
         * Parse a {@link CertificateStatusRequest} from an {@link InputStream}.
         * 
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link CertificateStatusRequest} object.
         * @throws IOException
         */
        public static CertificateStatusRequest parse(Stream input)
        {
            short status_type = TlsUtilities.ReadUint8(input);
            Object result = null;

            switch (status_type)
            {
                case (short)CertificateStatusType.ocsp:
                    result = OCSPStatusRequest.Parse(input);
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            return new CertificateStatusRequest(status_type, result);
        }

        protected static bool isCorrectType(short statusType, Object request)
        {
            switch (statusType)
            {
                case (short)CertificateStatusType.ocsp:
                    return request is OCSPStatusRequest;
                default:
                    throw new ArgumentException("'statusType' is an unsupported value");
            }
        }
    }
}