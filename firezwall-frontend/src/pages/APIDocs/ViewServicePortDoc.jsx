// =====================================================
// View Common Service Port Endpoint Content Component
// Location: /src/pages/APIDocs/ViewServicePortDoc.jsx
// =====================================================

const ViewServicePortEndpointContent = ({ activeTab, setActiveTab }) => (
    <div className="space-y-6">
      {/* Endpoint Header with Access Control Badge */}
      <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className="bg-blue-500/20 text-blue-400 px-3 py-1 rounded text-sm font-mono">
              GET
            </span>
            <code className="text-2xl font-bold text-white">/api/firewall/svc-port</code>
          </div>
        </div>
    
        <p className="text-slate-400 text-lg">
            Retrieve a list of all current included service ports for the service parameter of add and delete firewall rule endpoint.
        </p>

        </div>

    {/* Headers */}
    <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700/50">
    <h3 className="text-lg font-bold text-white mb-4">Headers</h3>
    <table className="w-full">
        <tbody>
        <tr className="border-b border-slate-700">
            <td className="py-3 text-slate-400 font-mono">Authorization</td>
            <td className="py-3 text-slate-300">
            Bearer &lt;access_token&gt;
            </td>
        </tr>
        </tbody>
    </table>
    </div>

    {/* Request Samples */}
    <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
    <div className="border-b border-slate-700/50">
        <div className="flex gap-2 p-4">
        {['basic', 'python', 'javascript', 'shell'].map((tab) => (
            <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === tab
                ? 'bg-orange-500 text-white'
                : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
            }`}
            >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
        ))}
        </div>
    </div>

    <div className="p-6">
        <h3 className="text-lg font-bold text-white mb-4">Request Sample</h3>
        
        {activeTab === 'basic' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`GET /api/firewall/svc-port

Header:
{
  'Authorization': 'Bearer <token>'
}
`}
        </pre>
        )}

        {activeTab === 'python' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`import requests

endpoint = "https://<server_ip>:5000/api/firewall/svc-port"

headers = {
    'Authorization': 'Bearer <access_token>'
}

r = requests.get(
    endpoint,
    headers=headers,
    verify=False
)

print(r.json())`}
        </pre>
        )}

        {activeTab === 'javascript' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`const response = await fetch('https://<server_ip>:5000/api/firewall/svc-port', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer <access_token>'
    }
});

const data = await response.json();
console.log(data);`}
        </pre>
        )}

        {activeTab === 'shell' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`curl -X get https://<server_ip>:5000/api/firewall/svc-port \\
    -H "Authorization: Bearer <access_token>"`}
        </pre>
        )}
    </div>
    </div>

    {/* Response Sample */}
    <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700/50">
    <h3 className="text-lg font-bold text-white mb-4">Response Sample</h3>
    
    <div className="space-y-4">
        <div>
        <h4 className="text-sm font-semibold text-green-400 mb-2">Success Response (200 OK)</h4>
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`{
  "success": True,
  "count": "int",
  "service ports": "JSON"
}`}
        </pre>
        </div>

        <div>
        <h4 className="text-sm font-semibold text-red-400 mb-2">Error Response</h4>
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`{
  "success": False,
  "error": "string"
}`}
        </pre>
        </div>
    </div>
    </div>
</div>
);

export default ViewServicePortEndpointContent;