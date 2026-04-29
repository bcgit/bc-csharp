using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Ocsp
{
    public class RespData
        : X509ExtensionBase
    {
        internal readonly ResponseData m_data;

        public RespData(ResponseData data)
        {
            m_data = data ?? throw new ArgumentNullException(nameof(data));
        }

        public int Version => m_data.Version.IntValueExact + 1;

        public RespID GetResponderId() => new RespID(m_data.ResponderID);

        public DateTime ProducedAt => m_data.ProducedAt.ToDateTime();

        public SingleResp[] GetResponses() =>
            m_data.Responses.MapElements(element => new SingleResp(SingleResponse.GetInstance(element)));

        public X509Extensions ResponseExtensions => m_data.ResponseExtensions;

        protected override X509Extensions GetX509Extensions() => ResponseExtensions;
    }
}
