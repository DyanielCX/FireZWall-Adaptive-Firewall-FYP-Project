// ==================================================
// Delete User Endpoint Content Component
// Location: /src/pages/APIDocs/DeleteUserDoc.jsx
// ==================================================

const DeleteUsersEndpointContent = ({ activeTab, setActiveTab }) => (
    <div className="space-y-6">
      {/* Endpoint Header with Access Control Badge */}
      <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className="bg-red-500/20 text-red-400 px-3 py-1 rounded text-sm font-mono">
              DELETE
            </span>
            <code className="text-2xl font-bold text-white">/api/user/delete</code>
          </div>
    </div>
    
    <p className="text-slate-400 text-lg">
        Delete the existing user from system.
    </p>
    
    {/* Access Control Warning Box */}
    <div className="mt-4 bg-red-500/5 border border-red-500/20 rounded-lg p-4">
        <div className="flex gap-3">
        <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
            <div className="text-red-400 font-semibold text-sm mb-1">Access Restriction</div>
            <div className="text-slate-400 text-sm">
            Only users with <code className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded">admin</code> role can access this endpoint. 
            Regular users will receive a <code className="text-orange-400">403 Forbidden</code> error.
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
            <td className="py-3 text-slate-300">
            Bearer &lt;access_token&gt;
            <span className="ml-2 text-red-400 text-sm">(Admin role required)</span>
            </td>
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
                <td className="py-3 px-4 text-orange-400 font-mono">username</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-green-400">true</td>
                <td className="py-3 px-4 text-slate-400">
                    Username of the account that want to delete
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
{`DELETE /api/user/delete

Header:
{
  'Content-Type': 'application/json',
  'Authorization': 'Bearer <token>'
}

Body:
{
  "username": "<username>"
}
`}
        </pre>
        )}

        {activeTab === 'python' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`import requests

endpoint = "https://<server_ip>:5000/api/user/delete"

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <access_token>'  # Must be admin token
}

body = {
    "username": "<username>"
}

r = requests.delete(
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
{`const response = await fetch('https://<server_ip>:5000/api/user/delete', {
    method: 'DELETE',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <access_token>'  // Must be admin token
    },
    body: JSON.stringify({
        "username": "<username>"
    })
});

const data = await response.json();
console.log(data);`}
        </pre>
        )}

        {activeTab === 'shell' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`curl -X DELETE https://<server_ip>:5000/api/user/delete \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer <access_token>" \\
    -d '{"username": "<username>"}'`}
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
  "messages": "string"
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

export default DeleteUsersEndpointContent;