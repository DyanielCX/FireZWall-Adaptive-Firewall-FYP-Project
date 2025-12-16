// ==================================================
// Refresh Token Endpoint Content Component
// Location: /src/pages/APIDocs/RefreshTokenDoc.jsx
// ==================================================

const RefreshTokenEndpointContent = ({ activeTab, setActiveTab }) => (
    <div className="space-y-6">
      {/* Endpoint Header */}
      <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
        <div className="flex items-center gap-3 mb-4">
          <span className="bg-green-500/20 text-green-400 px-3 py-1 rounded text-sm font-mono">
            POST
          </span>
          <code className="text-2xl font-bold text-white">/api/refresh-token</code>
        </div>
        <p className="text-slate-400 text-lg">
          Use refresh token to get a new access token without re-entering credentials.
        </p>
      </div>
  
      {/* Headers */}
      <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700/50">
        <h3 className="text-lg font-bold text-white mb-4">Headers</h3>
        <table className="w-full">
          <tbody>
            <tr className="border-b border-slate-700">
              <td className="py-3 text-slate-400 font-mono">Content-Type</td>
              <td className="py-3 text-slate-300">application/json</td>
            </tr>
          </tbody>
        </table>
      </div>
  
      {/* Parameters */}
      <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700/50">
        <h3 className="text-lg font-bold text-white mb-4">Parameters</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-slate-400 font-semibold">Name</th>
                <th className="text-left py-3 px-4 text-slate-400 font-semibold">Type</th>
                <th className="text-left py-3 px-4 text-slate-400 font-semibold">Required</th>
                <th className="text-left py-3 px-4 text-slate-400 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">refresh_token</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-green-400">true</td>
                <td className="py-3 px-4 text-slate-400">The refresh token from login response</td>
              </tr>
            </tbody>
          </table>
        </div>
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
{`POST /api/refresh-token

Header:
{
  'Content-Type': 'application/json'
}

Body:
{
  "refresh_token": "<refresh_token>"
}`}
            </pre>
          )}
  
          {activeTab === 'python' && (
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`import requests

endpoint = "https://<server_ip>:5000/api/refresh-token"

headers = {
    'Content-Type': 'application/json'
}

body = {
    "refresh_token": "<refresh_token>"
}

r = requests.post(
    endpoint,
    json=body,
    headers=headers,
    verify=False
)

print(r.json())`}
            </pre>
          )}
  
          {activeTab === 'javascript' && (
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`const response = await fetch('https://<server_ip>:5000/api/refresh-token', {
  method: 'POST',
  headers: {
      'Content-Type': 'application/json'
  },
  body: JSON.stringify({
      refresh_token: "<refresh_token>"
  })
});

const data = await response.json();
console.log(data);`}
            </pre>
          )}
  
          {activeTab === 'shell' && (
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
  {`curl -X POST https://<server_ip>:5000/api/refresh-token \\
    -H "Content-Type: application/json" \\
    -d '{"refresh_token":"<refresh_token>"}'`}
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
  "access_token": "string",
  "refresh_token": "string",
  "expires_in": "int",
  "token_type": "string"
}`}
        </pre>
        </div>

        <div>
        <h4 className="text-sm font-semibold text-red-400 mb-2">Error Response</h4>
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`{
  "error": "string"
}`}
        </pre>
        </div>
    </div>
    </div>
</div>
);

export default RefreshTokenEndpointContent;