using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>The signed portion (ResponseData) of a basic OCSP response.</summary>
    public class RespData
        : X509ExtensionBase
    {
        internal readonly ResponseData m_data;

        /// <summary>Create from an ASN.1 ResponseData structure.</summary>
        /// <param name="data">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
        public RespData(ResponseData data)
        {
            m_data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>Gets the version of the response data, as a one-based number (1 for v1).</summary>
        public int Version => m_data.Version.IntValueExact + 1;

        /// <summary>Return the identifier of the responder that produced this data.</summary>
        public RespID GetResponderId() => new RespID(m_data.ResponderID);

        /// <summary>Gets the time at which the responder signed this data.</summary>
        public DateTime ProducedAt => m_data.ProducedAt.ToDateTime();

        /// <summary>Return the individual certificate status responses.</summary>
        public SingleResp[] GetResponses() =>
            m_data.Responses.MapElements(element => new SingleResp(SingleResponse.GetInstance(element)));

        /// <summary>Gets the extensions that apply to the response as a whole, or null if there are none.</summary>
        public X509Extensions ResponseExtensions => m_data.ResponseExtensions;

        /// <inheritdoc/>
        protected override X509Extensions GetX509Extensions() => ResponseExtensions;
    }
}
