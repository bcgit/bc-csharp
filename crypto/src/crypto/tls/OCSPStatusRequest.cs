using System.IO;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls 
{

/**
 * RFC 3546 3.6
 */
public class OCSPStatusRequest
{
    protected IList responderIDList;
    protected X509Extensions requestExtensions;

    /**
     * @param responderIDList
     *            a {@link IList} of {@link ResponderID}, specifying the list of trusted OCSP
     *            responders. An empty list has the special meaning that the responders are
     *            implicitly known to the server - e.g., by prior arrangement.
     * @param requestExtensions
     *            OCSP request extensions. A null value means that there are no extensions.
     */
    public OCSPStatusRequest(IList responderIDList, X509Extensions requestExtensions)
    {
        this.responderIDList = responderIDList;
        this.requestExtensions = requestExtensions;
    }

    /**
     * @return a {@link IList} of {@link ResponderID}
     */
    public IList ResponderIDList
    {
        get
        {
            return responderIDList;
        }
    }

    /**
     * @return OCSP request extensions
     */
    public X509Extensions RequestExtensions
    {
        get
        {
            return requestExtensions;
        }
    }

    /**
     * Encode this {@link OCSPStatusRequest} to an {@link Stream}.
     * 
     * @param output
     *            the {@link Stream} to encode to.
     * @throws IOException
     */
    
    public void Encode(Stream output) 
    {
        if (responderIDList == null || responderIDList.Count == 0)
        {
            TlsUtilities.WriteUint16(0, output);
        }
        else
        {
            MemoryStream buf = new MemoryStream();
            foreach (ResponderID responderID in responderIDList)
            {
                byte[] derEncoding = responderID.GetDerEncoded();
                TlsUtilities.WriteOpaque16(derEncoding, buf);
            }
            TlsUtilities.CheckUint16((int)buf.Length);
            TlsUtilities.WriteUint16((int)buf.Length, output);
            buf.WriteTo(output);
        }

        if (requestExtensions == null)
        {
            TlsUtilities.WriteUint16(0, output);
        }
        else
        {
            byte[] derEncoding = requestExtensions.GetDerEncoded();
            TlsUtilities.CheckUint16(derEncoding.Length);
            TlsUtilities.WriteUint16(derEncoding.Length, output);
            output.Write(derEncoding, 0, derEncoding.Length);
        }
    }

    /**
     * Parse a {@link OCSPStatusRequest} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link OCSPStatusRequest} object.
     * @throws IOException
     */
    public static OCSPStatusRequest Parse(Stream input) 
    {
        IList responderIDList = Platform.CreateArrayList();
        {
            int length = TlsUtilities.ReadUint16(input);
            if (length > 0)
            {
                byte[] data = TlsUtilities.ReadFully(length, input);
                MemoryStream buf = new MemoryStream(data);
                do
                {
                    byte[] derEncoding = TlsUtilities.ReadOpaque16(buf);
                    ResponderID responderID = ResponderID.GetInstance(TlsUtilities.ReadDerObject(derEncoding));
                    responderIDList.Add(responderID);
                }
                while (buf.Length > 0);
            }
        }

        X509Extensions requestExtensions = null;
        {
            int length = TlsUtilities.ReadUint16(input);
            if (length > 0)
            {
                byte[] derEncoding = TlsUtilities.ReadFully(length, input);
                requestExtensions = X509Extensions.GetInstance(TlsUtilities.ReadDerObject(derEncoding));
            }
        }

        return new OCSPStatusRequest(responderIDList, requestExtensions);
    }
}
}