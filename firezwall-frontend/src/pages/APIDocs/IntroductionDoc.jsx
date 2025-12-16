// ==================================================
// Introduction Content Component
// Location: /src/pages/APIDocs/IntroductionDoc.jsx
// ==================================================

const IntroductionContent = () => (
  <div className="space-y-6">
    <div className="bg-slate-800/50 rounded-lg p-8 border border-slate-700/50">
      <h1 className="text-3xl font-bold text-white mb-4">FireZWall API Documentation</h1>
      <p className="text-slate-300 text-lg mb-6">
        Welcome to the FireZWall API documentation. This API allows you to manage firewall rules, 
        monitor honeypot activities and access system logs programmatically.
      </p>

      <div className="space-y-8">
        <div>
          <h2 className="text-xl font-bold text-white mb-3">Base URL</h2>
          <code className="bg-slate-900/50 text-orange-400 px-4 py-2 rounded-lg block">
            https://&lt;server_ip&gt;:5000/api
          </code>
        </div>

        <div>
          <h2 className="text-xl font-bold text-white mb-3">Authentication</h2>
          <p className="text-slate-400 mb-3">
            Most endpoints require authentication using a Bearer token. To authenticate:
          </p>
          <ol className="list-decimal list-inside space-y-2 text-slate-400 ml-4">
            <li>Obtain an access token by calling the <code className="text-orange-400">/api/login</code> endpoint</li>
            <li>Include the token in the Authorization header: <code className="text-orange-400">Authorization: Bearer &lt;token&gt;</code></li>
            <li>Tokens expire after <span className="text-orange-400 font-semibold">1 hour</span>. Use the refresh token endpoint to get a new access token</li>
          </ol>
        </div>

        <div>
          <h2 className="text-xl font-bold text-white mb-3">Authorization</h2>
          <p className="text-slate-400 mb-3">
            Some of the endpoint have set with the access control and limit for specific role access only.
            The specific role will be mentioned in API docs if the endpoint has applied access control.
          </p>
        </div>

        <div>
          <h2 className="text-xl font-bold text-white mb-3">Accounting</h2>
          <p className="text-slate-400 mb-3">
            All the API endpoints are under the system monitor and will be seved as system logs. 
            To view system log:
          </p>
          <ol className="list-decimal list-inside space-y-2 text-slate-400 ml-4">
            <li>Obtain an access token by calling the <code className="text-orange-400">/api/login</code> endpoint</li>
            <li>Call the <code className="text-orange-400">/api/logs</code> endpoint and include the access token in Authorization header</li>
            <li>Users can view all their own system logs from the API response. While admin role able to view all user system logs</li>
          </ol>
        </div>

        <div>
          <h2 className="text-xl font-bold text-white mb-3">Response Format</h2>
          <p className="text-slate-400 mb-3">
            All responses are returned in JSON format. Successful responses typically include:
          </p>
          <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}`}
          </pre>
        </div>

        <div>
          <h2 className="text-xl font-bold text-white mb-3">Error Handling</h2>
          <p className="text-slate-400 mb-3">
            Error responses include an error message and appropriate HTTP status code:
          </p>
          <pre className="bg-slate-900/50 text-slate-300 p-4 rounded-lg overflow-x-auto">
{`{
  "success": false,
  "error": "Error description"
}`}
          </pre>
        </div>
      </div>
    </div>
  </div>
);

export default IntroductionContent;