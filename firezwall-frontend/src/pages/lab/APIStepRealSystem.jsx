// ============================================
// API Steps in Real-System Page
// Location: /src/pages/lab/APIStepsRealSystem.jsx
// ============================================
import { 
    Code, Terminal, AlertTriangle, Info, 
    CheckCircle, ExternalLink, Layers, Zap, 
    BookOpen, Shield
  } from 'lucide-react';
  import Card from '../../components/ui/Card';
  import Button from '../../components/ui/Button';
  
  const APIStepsRealSystem = ({ onNavigate }) => {
    const handleLearnMore = () => {
      window.open('https://learning.postman.com/docs/introduction/overview/', '_blank');
    };
  
    const handlePostmanVariables = () => {
      window.open('https://learning.postman.com/docs/sending-requests/variables/variables-intro/', '_blank');
    };
  
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-3 rounded-lg">
              <Code className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Step into Real-System - API Configuration</h1>
              <p className="text-slate-400 mt-1">
                Learn how to configure firewall rules using API requests in production
              </p>
            </div>
          </div>
        </div>
  
        {/* Important Warning */}
        <Card className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-500/30">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-xl font-bold text-white mb-2"> Before You Begin</h3>
              <p className="text-slate-300 mb-3">
                API-based firewall configuration requires understanding of HTTP requests, authentication 
                and JSON data structures. Incorrect API calls can lead to security vulnerabilities.
              </p>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <p className="text-orange-400 font-semibold mb-2 flex items-center gap-2">
                  <Info className="w-4 h-4" />
                  Recommended Preparation
                </p>
                <p className="text-slate-300 text-sm">
                  Complete the <button 
                    onClick={() => onNavigate('api-learning')}
                    className="text-orange-500 hover:text-orange-400 underline font-semibold"
                  >
                    API Learning
                  </button> section first, then practice requests in the <button 
                    onClick={() => onNavigate('api-practice')}
                    className="text-orange-500 hover:text-orange-400 underline font-semibold"
                  >
                    API Request Practice
                  </button> environment before working on the actual system.
                </p>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Introduction */}
        <Card>
          <h2 className="text-2xl font-bold text-white mb-4">Three Methods to Send API Requests</h2>
          <p className="text-slate-300 mb-4">
            There are three primary ways to interact with the FireZWall API to configure firewall rules:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gradient-to-br from-slate-700/30 to-slate-800/30 rounded-lg p-4 border border-slate-600">
              <div className="flex items-center gap-2 mb-2">
                <Terminal className="w-5 h-5 text-slate-400" />
                <h3 className="text-lg font-semibold text-white">CLI Command</h3>
              </div>
              <p className="text-slate-400 text-sm">Using curl in terminal</p>
            </div>
            <div className="bg-gradient-to-br from-purple-700/30 to-pink-800/30 rounded-lg p-4 border border-purple-600">
              <div className="flex items-center gap-2 mb-2">
                <Code className="w-5 h-5 text-purple-400" />
                <h3 className="text-lg font-semibold text-white">Python/JavaScript</h3>
              </div>
              <p className="text-purple-400 text-sm">Programmatic automation</p>
            </div>
            <div className="bg-gradient-to-br from-blue-700/30 to-cyan-800/30 rounded-lg p-4 border border-blue-600">
              <div className="flex items-center gap-2 mb-2">
                <Layers className="w-5 h-5 text-blue-400" />
                <h3 className="text-lg font-semibold text-white">API Testing Platform</h3>
              </div>
              <p className="text-blue-400 text-sm font-semibold">✓ Recommended for Beginners</p>
            </div>
          </div>
        </Card>
  
        {/* Method 1: CLI Command */}
        <Card className="border-slate-600">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-slate-700/50 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-slate-300 font-bold text-xl">1</span>
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-2">Method 1: CLI Command (curl)</h2>
              <p className="text-slate-300">
                Use the curl command-line tool to send HTTP requests directly from your terminal.
              </p>
            </div>
          </div>
  
          {/* Characteristics */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Characteristics:</h3>
            <ul className="space-y-2">
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Fast and lightweight - no additional tools needed</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Requires command-line knowledge and syntax understanding</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <span>Can be scripted for automation</span>
              </li>
            </ul>
          </div>
  
          {/* Example */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Example Request:</h3>
            <div className="bg-slate-900 rounded-lg p-4 border border-slate-700 overflow-x-auto">
              <code className="text-green-400 text-sm font-mono whitespace-pre">
  {`curl -X POST https://localhost:5000/api/firewall \\
    -H "Authorization: Bearer <ACCESS_TOKEN>" \\
    -H "Content-Type: application/json" \\
    -d '{"action":"allow","port":8080,"proto":"tcp"}'`}
              </code>
            </div>
          </div>
  
          {/* Suitability */}
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-lg font-semibold text-yellow-400 mb-2">Not Recommended for Beginners</h3>
                <ul className="space-y-1.5 text-sm text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-400">•</span>
                    <span>Requires familiarity with command-line syntax</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-400">•</span>
                    <span>Difficult to debug errors without visual feedback</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-400">•</span>
                    <span>Easy to make syntax mistakes with quotes and escaping</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Method 2: Python/JavaScript */}
        <Card className="border-purple-600">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-purple-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-purple-400 font-bold text-xl">2</span>
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-white mb-2">Method 2: Python/JavaScript</h2>
              <p className="text-slate-300">
                Write code to send API requests programmatically for automation and integration.
              </p>
            </div>
          </div>
  
          {/* Characteristics */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Characteristics:</h3>
            <ul className="space-y-2">
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <span>Perfect for building automated workflows and scripts</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <span>Requires programming knowledge (Python or JavaScript)</span>
              </li>
              <li className="flex items-start gap-3 text-slate-300">
                <CheckCircle className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <span>Enables complex logic and error handling</span>
              </li>
            </ul>
          </div>
  
          {/* Example */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Example (Python):</h3>
            <div className="bg-slate-900 rounded-lg p-4 border border-slate-700 overflow-x-auto">
              <code className="text-cyan-400 text-sm font-mono whitespace-pre">
  {`import requests

endpoint = "https://localhost:5000/api/firewall"

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer <access_token>'  # Must be admin/dev/cybersec token
}

body = {
    "action": "allow",
    "port": "8080",
    "protocol": "tcp"
}

r = requests.post(
    endpoint,
    json=body,
    headers=headers,
    verify=False
)

print(r.json())`}
              </code>
            </div>
          </div>
  
          {/* Suitability */}
          <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Zap className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-lg font-semibold text-purple-400 mb-2">Best for Automation</h3>
                <ul className="space-y-1.5 text-sm text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400">•</span>
                    <span>Ideal for scheduled tasks and bulk operations</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400">•</span>
                    <span>Integrate with existing DevOps workflows</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400">•</span>
                    <span>Requires coding skills - not beginner-friendly</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Method 3: API Testing Platform */}
        <Card className="border-blue-600">
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-blue-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-blue-400 font-bold text-xl">3</span>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <h2 className="text-2xl font-bold text-white">Method 3: API Testing Platform</h2>
                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs font-semibold rounded border border-blue-500/30">
                  RECOMMENDED
                </span>
              </div>
              <p className="text-slate-300">
                Use visual tools like Postman or Burp Suite with GUI-based API testing experience.
              </p>
            </div>
          </div>
  
          {/* Benefits */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Why This Method is Best for Beginners:</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <h4 className="font-semibold text-white text-sm">User-Friendly Interface</h4>
                </div>
                <p className="text-slate-300 text-sm">Visual forms and buttons instead of command syntax</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle className="w-4 h-4 text-blue-400" />
                  <h4 className="font-semibold text-white text-sm">Easy to Learn</h4>
                </div>
                <p className="text-slate-300 text-sm">No programming knowledge required</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Info className="w-4 h-4 text-blue-400" />
                  <h4 className="font-semibold text-white text-sm">Visual Feedback</h4>
                </div>
                <p className="text-slate-300 text-sm">See request/response details instantly</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Layers className="w-4 h-4 text-blue-400" />
                  <h4 className="font-semibold text-white text-sm">Save & Organize</h4>
                </div>
                <p className="text-slate-300 text-sm">Store requests in collections for reuse</p>
              </div>
            </div>
          </div>
  
          {/* Postman Example */}
          <div className="mb-4">
            <h3 className="text-lg font-semibold text-white mb-3">Example: Using Postman</h3>
            <p className="text-slate-300 mb-3">
              Below is how you would configure a firewall rule addition request in Postman:
            </p>
  
            {/* Step 1: Headers */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold">
                  1
                </div>
                <h4 className="font-semibold text-white">Configure Headers</h4>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">Set authorization header:</p>
                <p className="text-slate-400 text-sm mb-3">The content type will auto added in Postman if your body in JSON format</p>
                
                {/* Postman Headers Screenshot */}
                <div className="mt-4">
                  <img 
                    src="/img/postman-request-header.png" 
                    alt="Postman Headers Configuration"
                    className="w-full rounded-lg border border-slate-600"
                  />
                </div>
              </div>
            </div>
  
            {/* Step 2: Body */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold">
                  2
                </div>
                <h4 className="font-semibold text-white">Configure Request Body</h4>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">Select "raw", then add the request body in JSON format:</p>
                
                {/* Postman Body Screenshot */}
                <div className="mt-4">
                  <img 
                    src="/img/postman-request-body.png" 
                    alt="Postman Request Body Configuration"
                    className="w-full rounded-lg border border-slate-600"
                  />
                </div>
              </div>
            </div>
  
            {/* Step 3: Response */}
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="bg-blue-500 text-white w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold">
                  3
                </div>
                <h4 className="font-semibold text-white">View Response</h4>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-300 mb-3">After clicking "Send", you'll see the API response:</p>
                
                {/* Postman Response Screenshot */}
                <div className="mt-4">
                  <img 
                    src="/img/postman-response.png" 
                    alt="Postman Response"
                    className="w-full rounded-lg border border-slate-600"
                  />
                </div>
              </div>
            </div>
          </div>
  
          {/* Postman Variables Note */}
          <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4 mb-4">
            <div className="flex items-start gap-3">
              <Info className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Using Environment Variables</h3>
                <p className="text-slate-300 text-sm mb-2">
                  You may see <code className="text-cyan-400 bg-slate-800 px-2 py-0.5 rounded font-mono text-xs">{`{{server_ip}}`}</code> in 
                  API endpoint URLs. This is a Postman environment variable that can be configured for reused data.
                </p>
                <p className="text-slate-300 text-sm">
                  Example: <code className="text-green-400 bg-slate-800 px-2 py-0.5 rounded font-mono text-xs">{`http://{{server_ip}}:5000/api/firewall`}</code>
                </p>
                <button
                  onClick={handlePostmanVariables}
                  className="mt-3 text-cyan-400 hover:text-cyan-300 text-sm flex items-center gap-1 underline"
                >
                  <BookOpen className="w-4 h-4" />
                  Learn more about Postman environment variables
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
  
          {/* Popular Tools */}
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-white mb-3">Popular API Testing Platforms:</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <h4 className="font-semibold text-blue-400 mb-1">Postman</h4>
                <p className="text-slate-300 text-sm">Most popular & user-friendly with extensive documentation</p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <h4 className="font-semibold text-blue-400 mb-1">Burp Suite</h4>
                <p className="text-slate-300 text-sm">Advanced features for security testing</p>
              </div>
            </div>
          </div>
        </Card>
  
        {/* Learn More Section */}
        <Card className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-cyan-500/30">
          <div className="text-center py-6">
            <BookOpen className="w-12 h-12 text-cyan-500 mx-auto mb-3" />
            <h3 className="text-xl font-bold text-white mb-3">Want to Learn More About Postman?</h3>
            <p className="text-slate-300 max-w-2xl mx-auto mb-6">
              Postman offers comprehensive documentation to help you master API testing. 
              From basics to advanced features, their documentation has everything you need.
            </p>
            <Button
              onClick={handleLearnMore}
              className="flex items-center gap-2 mx-auto"
            >
              <ExternalLink className="w-4 h-4" />
              View Postman Documentation
            </Button>
          </div>
        </Card>
  
        {/* Next Steps */}
        <Card className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-purple-500/30">
          <div className="text-center py-6">
            <Code className="w-12 h-12 text-purple-500 mx-auto mb-3" />
            <h3 className="text-xl font-bold text-white mb-3">Ready to Practice?</h3>
            <p className="text-slate-300 max-w-2xl mx-auto mb-6">
              Now you have understand the different methods to send API requests, 
              practice them in a safe environment before working on the production server.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <button
                onClick={() => onNavigate('api-learning')}
                className="px-6 py-2.5 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-all flex items-center gap-2 justify-center"
              >
                <Shield className="w-4 h-4" />
                Review API Basics
              </button>
              <button
                onClick={() => onNavigate('api-practice')}
                className="px-6 py-2.5 bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 text-white rounded-lg transition-all flex items-center gap-2 justify-center font-semibold"
              >
                <Code className="w-4 h-4" />
                Start API Request Practice
              </button>
            </div>
          </div>
        </Card>
      </div>
    );
  };
  
  export default APIStepsRealSystem;