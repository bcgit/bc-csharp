using System;
using System.IO;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Crypto.Tls {

public class CertificateStatus
{
    protected CertificateStatusType statusType;
    protected Object response;

    public CertificateStatus(CertificateStatusType statusType, Object response)
    {
        if (!IsCorrectType(statusType, response))
        {
            throw new ArgumentException("'response' is not an instance of the correct type");
        }
        
        this.statusType = statusType;
        this.response = response;
    }

    public CertificateStatusType StatusType
    {
        get
        {
            return statusType;
        }
    }

    public Object GetResponse()
    {
        return response;
    }

    public OcspResponse getOCSPResponse()
    {
        if (!IsCorrectType(CertificateStatusType.ocsp, response))
        {
            throw new InvalidOperationException("'response' is not an OCSPResponse");
        }
        return (OcspResponse)response;
    }

    /**
     * Encode this {@link CertificateStatus} to an {@link Stream}.
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
            byte[] derEncoding = ((OcspResponse) response).GetDerEncoded();
            TlsUtilities.WriteOpaque24(derEncoding, output);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link CertificateStatus} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link CertificateStatus} object.
     * @throws IOException
     */
    public static CertificateStatus parse(Stream input)
    {
        CertificateStatusType status_type = (CertificateStatusType)TlsUtilities.ReadUint8(input);
        Object response;

        switch (status_type)
        {
            case CertificateStatusType.ocsp:
                {
                    byte[] derEncoding = TlsUtilities.ReadOpaque24(input);
                    response = OcspResponse.GetInstance(TlsUtilities.ReadDerObject(derEncoding));
                    break;
                }
            default:
                throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new CertificateStatus(status_type, response);
    }

    protected static bool IsCorrectType(CertificateStatusType statusType, Object response)
    {
        switch (statusType)
        {
        case CertificateStatusType.ocsp:
            return response is OcspResponse;
        default:
            throw new ArgumentException("'statusType' is an unsupported value");
        }
    }
}

}