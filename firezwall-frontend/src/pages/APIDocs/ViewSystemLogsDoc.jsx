// ==================================================
// View System Logs Endpoint Content Component
// Location: /src/pages/APIDocs/ViewSystemLogsDoc.jsx
// ==================================================

const ViewSystemLogsEndpointContent = ({ activeTab, setActiveTab }) => (
    <div className="space-y-6">
      {/* Endpoint Header */}
      <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
        <div className="flex items-center gap-3 mb-4">
          <span className="bg-green-500/20 text-green-400 px-3 py-1 rounded text-sm font-mono">
            POST
          </span>
          <code className="text-2xl font-bold text-white">/api/logs</code>
        </div>
        <p className="text-slate-400 text-lg mb-4">
          Retrieve system logs based on user role and optional filters.
        </p>
  
        {/* Role-Based Access Info Box */}
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-5">
          <div className="flex gap-3">
            <svg className="w-6 h-6 text-blue-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="space-y-3">
                <div>
                    <div className="text-blue-400 font-semibold text-base mb-2">Role-Based Log Access</div>
                    <div className="text-slate-400 text-sm space-y-2">
                    <div className="flex items-start gap-2">
                        <div className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-xs font-semibold mt-0.5 w-14 text-center">
                        ADMIN
                        </div>
                        <div>Can view <span className="text-white font-semibold">all users' system logs</span> including their own</div>
                    </div>
                    <div className="flex items-start gap-2">
                        <div className="bg-green-500/20 text-green-400 px-2 py-0.5 rounded text-xs font-semibold mt-0.5 w-14 text-center">
                        USER
                        </div>
                        <div>Can only view <span className="text-white font-semibold">their own system logs</span></div>
                    </div>
                    </div>
                </div>
            </div>
          </div>
        </div>
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
            <tr className="border-b border-slate-700">
              <td className="py-3 text-slate-400 font-mono">Authorization</td>
              <td className="py-3 text-slate-300">Bearer &lt;access_token&gt;</td>
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
                <td className="py-3 px-4 text-orange-400 font-mono">timestamp</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4 text-slate-400">
                  <div className="space-y-1">
                      <div className="text-slate-400">
                      Filters system logs based on the event timestamp
                      </div>
                      <div className="text-slate-500 text-sm">
                          Format: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">YYYY-MM-DD</code> / 
                          <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">YYYY-MM</code> / 
                          <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">YYYY</code>
                      </div>
                  </div>
                </td>
              </tr>
              <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">level</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4 text-slate-400">
                  Filters system logs by the level of logs
                  <span className="text-orange-400"> (info/warning/error)</span>
                </td>
              </tr>
              <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">module</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4 text-slate-400">
                  Filters system logs according to the module
                  <span className="text-orange-400"> (auth/firewall/honeypot/syslog)</span>
                </td>
              </tr>
              <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">username</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        Filter the system logs based on the username
                        </div>
                        <div className="text-red-500 text-sm">
                        Only user with <code className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">admin</code> role
                        can apply this parameter
                        </div>
                    </div>
                </td>
              </tr>
              <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">endpoint</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4 text-slate-400">
                  <div className="space-y-1">
                      <div className="text-slate-400">
                      Filters system logs through the endpoint
                      </div>
                      <div className="text-slate-500 text-sm">
                          Format: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">/api/xxx/xxx</code>
                      </div>
                  </div>
                </td>
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
{`POST /api/logs

Header:
{
  'Content-Type': 'application/json',
  'Authorization': 'Bearer <token>'
}

Body:
{
  "timestamp": "<timestamp>",
  "level": "<level>",
  "module": "<module>",
  "username": "<username>",
  "endpoint": "<endpoint>"
}

// Get all logs
{}`}
  

            </pre>
          )}
  
          {activeTab === 'python' && (
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`import requests

endpoint = "https://<server_ip>:5000/api/logs"

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <access_token>'
}

body = {
    "timestamp": "<timestamp>",
    "level": "<level>",
    "module": "<module>",
    "username": "<username>",
    "endpoint": "<endpoint>"
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
{`const response = await fetch('https://<server_ip>:5000/api/logs', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <access_token>'  // Must be admin/cybersec token
    },
    body: JSON.stringify({
          "timestamp": "<timestamp>",
          "level": "<level>",
          "module": "<module>",
          "username": "<username>",
          "endpoint": "<endpoint>"
    })
});

const data = await response.json();
console.log(data);`}
            </pre>
          )}
  
          {activeTab === 'shell' && (
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`curl -X POST https://<server_ip>:5000/api/honeypot/reports \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer <access_token>" \\
    -d '{"timestamp": "<timestamp>", "level": "<level>", "module": "<module>", \\
    "username": "<username>", "endpoint": "<endpoint>"}'`}
            </pre>
          )}
        </div>
      </div>
  
      {/* Response Sample */}
      <div className="bg-slate-800/50 rounded-lg p-6 border border-slate-700/50">
        <h3 className="text-lg font-bold text-white mb-4">Response Sample</h3>
        
        <div className="space-y-4">
          <div>
            <h4 className="text-sm font-semibold text-green-400 mb-2">Success Response</h4>
            <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
  {`{
    "success": True,
    "count": "int",
    "logs": "JSON"
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
  
  export default ViewSystemLogsEndpointContent;