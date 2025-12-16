// ==================================================
// Add Firewall Rule Endpoint Content Component
// Location: /src/pages/APIDocs/AddFirewallDoc.jsx
// ==================================================

const AddFirewallEndpointContent = ({ activeTab, setActiveTab }) => (
    <div className="space-y-6">
      {/* Endpoint Header with Access Control Badge */}
      <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <span className="bg-green-500/20 text-green-400 px-3 py-1 rounded text-sm font-mono">
              POST
            </span>
            <code className="text-2xl font-bold text-white">/api/firewall</code>
          </div>
    </div>
    
    <p className="text-slate-400 text-lg">
        Add a new UFW firewall rule with API request.
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
            Only users with <code className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded">admin</code> / 
            <code className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded">dev</code> / 
            <code className="text-red-400 bg-red-500/10 px-2 py-0.5 rounded">cybersec</code>
            role can access this endpoint. 
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
            <span className="ml-2 text-red-400 text-sm">(Admin / Developer / Cybersecurity role required)</span>
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
                <td className="py-3 px-4 text-orange-400 font-mono">action</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        Specifies the firewall action to apply to the rule
                            <span className="text-orange-400"> (allow/deny/reject)</span>
                        </div>
                        <div className="text-slate-500 text-sm">
                            Default: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">allow</code>
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">port</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        The network port number which the firewall rule applies
                            <span className="text-orange-400"> (1 - 65535)</span>
                        </div>
                        <div className="text-red-500 text-sm">
                        This parameter is required if <code className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">service</code> is not provided
                        and only provide either one
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">service</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        The common service name associated with a predefined port
                        </div>
                        <div className="text-red-500 text-sm">
                        This parameter is required if <code className="text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">port</code> is not provided
                        and only provide either one
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">protocol</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        Specifies the transport protocol used by the rule
                            <span className="text-orange-400"> (tcp/udp)</span>
                        </div>
                        <div className="text-slate-500 text-sm">
                            Default: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">tcp</code>
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">direction</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        Defines the traffic direction the rule applies to
                            <span className="text-orange-400"> (in/out)</span>
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">ipv4</td>
                <td className="py-3 px-4 text-slate-300">Boolean</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                <div className="space-y-1">
                        <div className="text-slate-400">
                        Indicates whether the firewall rule should be applied to IPv4 traffic
                        </div>
                        <div className="text-slate-500 text-sm">
                            Default: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">True</code>
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">ipv6</td>
                <td className="py-3 px-4 text-slate-300">Boolean</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                    <div className="space-y-1">
                        <div className="text-slate-400">
                        Indicates whether the firewall rule should be applied to IPv6 traffic
                        </div>
                        <div className="text-slate-500 text-sm">
                            Default: <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">True</code>
                        </div>
                    </div>
                </td>
            </tr>
            <tr className="border-b border-slate-700/50">
                <td className="py-3 px-4 text-orange-400 font-mono">source</td>
                <td className="py-3 px-4 text-slate-300">string</td>
                <td className="py-3 px-4 text-slate-400">false</td>
                <td className="py-3 px-4">
                <div className="space-y-1">
                        <div className="text-slate-400">
                        Specifies the source IP address or subnet allowed or denied by the rule
                        </div>
                        <div className="text-orange-500 text-sm">
                        If not provided, the rule applies to traffic from <code className="text-orange-400 bg-orange-500/10 px-1.5 py-0.5 rounded">any</code> source
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
{`POST /api/firewall

Header:
{
  'Content-Type': 'application/json',
  'Authorization': 'Bearer <token>'
}

Body:
{
  "action": "<action>",
  "port": "<port>",
  "protocol": "<protocol>",
  "direction": "<direction>",
  "ipv4": Boolean,
  "ipv6": Boolean,
  "source": "<source>"
}
`}
        </pre>
        )}

        {activeTab === 'python' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`import requests

endpoint = "https://<server_ip>:5000/api/firewall"

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <access_token>'  # Must be admin/dev/cybersec token
}

body = {
    "action": "<action>",
    "port": "<port>",
    "protocol": "<protocol>",
    "direction": "<direction>",
    "ipv4": Boolean,
    "ipv6": Boolean,
    "source": "<source>"
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
{`const response = await fetch('https://<server_ip>:5000/api/firewall', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <access_token>'  // Must be admin/dev/cybersec token
    },
    body: JSON.stringify({
          "action": "<action>",
          "port": "<port>",
          "protocol": "<protocol>",
          "direction": "<direction>",
          "ipv4": Boolean,
          "ipv6": Boolean,
          "source": "<source>"
    })
});

const data = await response.json();
console.log(data);`}
        </pre>
        )}

        {activeTab === 'shell' && (
        <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`curl -X POST https://<server_ip>:5000/api/firewall \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer <access_token>" \\
    -d '{"action": "<action>", "port": "<port>", "protocol": "<protocol>", \\
        "direction": "<direction>", "ipv4": Boolean, "ipv6": Boolean, "source": "<source>"}'`}
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

export default AddFirewallEndpointContent;