// ============================================
// API Learning Page
// Location: /src/pages/lab/APILearning.jsx
// ============================================

import { useState } from 'react';
import { 
  BookOpen, Code, Zap, Lock, ShieldCheck, 
  ArrowRight, CheckCircle, AlertTriangle, Info,
  Key, UserCheck, Clock, Database
} from 'lucide-react';
import Card from '../../components/ui/Card';

const APILearning = () => {
  const [activeTab, setActiveTab] = useState('intro');

  const tabs = [
    { id: 'intro', label: 'What is an API?', icon: BookOpen },
    { id: 'why', label: 'Why APIs Matter', icon: Zap },
    { id: 'how', label: 'How APIs Work', icon: ArrowRight },
    { id: 'concepts', label: 'Key Concepts', icon: Code },
    { id: 'security', label: 'Security & Auth', icon: Lock }
  ];

  const renderIntro = () => (
    <div className="space-y-6">
      {/* Hero */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="bg-blue-500/20 p-3 rounded-lg">
            <BookOpen className="w-8 h-8 text-blue-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-3">What is an API?</h2>
            <p className="text-slate-300 text-lg leading-relaxed">
              An <span className="text-blue-400 font-semibold">API (Application Programming Interface)</span> is 
              a communication bridge that allows different applications or systems to talk to each other.
            </p>
          </div>
        </div>
      </Card>

      {/* Core Concepts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-blue-500/30">
          <div className="flex items-center gap-3 mb-3">
            <div className="bg-blue-500/20 p-2 rounded-lg">
              <Code className="w-5 h-5 text-blue-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Structured Communication</h3>
          </div>
          <p className="text-slate-300 text-sm">
            APIs define how software can request and exchange data in a consistent, predictable way.
          </p>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/30">
          <div className="flex items-center gap-3 mb-3">
            <div className="bg-purple-500/20 p-2 rounded-lg">
              <ShieldCheck className="w-5 h-5 text-purple-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Hidden Complexity</h3>
          </div>
          <p className="text-slate-300 text-sm">
            Systems work together without exposing internal logic and keeping implementation details secure.
          </p>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/30">
          <div className="flex items-center gap-3 mb-3">
            <div className="bg-green-500/20 p-2 rounded-lg">
              <Zap className="w-5 h-5 text-green-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Automation Ready</h3>
          </div>
          <p className="text-slate-300 text-sm">
            Perfect for scripting, automation and building integrations between different platforms.
          </p>
        </Card>
      </div>

      {/* Simple Analogy */}
      <Card className="bg-gradient-to-r from-slate-800 to-slate-900 border-slate-700">
        <div className="flex items-start gap-4">
          <div className="bg-orange-500/20 p-3 rounded-lg flex-shrink-0">
            <Info className="w-6 h-6 text-orange-500" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white mb-3">Think of it Like a Restaurant</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-orange-400 font-semibold mb-1">You (Client)</p>
                <p className="text-slate-300">Order food from the menu</p>
              </div>
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-orange-400 font-semibold mb-1">Waiter (API)</p>
                <p className="text-slate-300">Takes your order to the kitchen</p>
              </div>
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-orange-400 font-semibold mb-1">Kitchen (Server)</p>
                <p className="text-slate-300">Prepares and returns your meal</p>
              </div>
            </div>
            <p className="text-slate-400 mt-3 text-sm">
              You don't need to know how the kitchen works — you just place your order (API request) 
              and receive your food (API response).
            </p>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderWhy = () => (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="bg-orange-500/20 p-3 rounded-lg">
            <Zap className="w-8 h-8 text-orange-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-2">Why APIs Matter in Cybersecurity</h2>
            <p className="text-slate-300 text-lg">
              APIs are the backbone of modern security automation and firewall management.
            </p>
          </div>
        </div>
      </Card>

      {/* Use Cases */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-orange-500/20 p-2 rounded-lg flex-shrink-0">
              <ShieldCheck className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Automate Firewall Configuration</h3>
              <p className="text-slate-300 text-sm">
                Add, update or remove firewall rules programmatically without manual GUI clicks.
              </p>
            </div>
          </div>
        </Card>

        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-blue-500/20 p-2 rounded-lg flex-shrink-0">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Collect Security Logs</h3>
              <p className="text-slate-300 text-sm">
                Retrieve system logs, honeypot reports and security events in real-time.
              </p>
            </div>
          </div>
        </Card>

        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-red-500/20 p-2 rounded-lg flex-shrink-0">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Trigger Security Responses</h3>
              <p className="text-slate-300 text-sm">
                Automatically block IPs, enable alerts or execute incident response workflows.
              </p>
            </div>
          </div>
        </Card>

        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-green-500/20 p-2 rounded-lg flex-shrink-0">
              <Zap className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Update Rules Dynamically</h3>
              <p className="text-slate-300 text-sm">
                Adjust firewall rules on-the-fly based on threat intelligence or traffic patterns.
              </p>
            </div>
          </div>
        </Card>

        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-purple-500/20 p-2 rounded-lg flex-shrink-0">
              <Code className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Integrate with Monitoring Tools</h3>
              <p className="text-slate-300 text-sm">
                Connect to SIEM systems, dashboards and alerting platforms for unified visibility.
              </p>
            </div>
          </div>
        </Card>

        <Card className="hover:border-orange-500/50 transition-all">
          <div className="flex items-start gap-3 mb-3">
            <div className="bg-cyan-500/20 p-2 rounded-lg flex-shrink-0">
              <CheckCircle className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white mb-2">Enable DevSecOps Workflows</h3>
              <p className="text-slate-300 text-sm">
                Embed security into CI/CD pipelines for automated testing and deployment.
              </p>
            </div>
          </div>
        </Card>
      </div>

      {/* System Context */}
      <Card className="bg-gradient-to-r from-orange-500/10 to-red-600/10 border-orange-500/30">
        <div className="text-center py-6">
          <h3 className="text-xl font-bold text-white mb-3">In This System</h3>
          <p className="text-slate-300 max-w-2xl mx-auto">
            Instead of clicking through the UI, you can use <span className="text-orange-500 font-semibold">API endpoints</span> to 
            manage firewall rules programmatically. This enables scripting, automation and integration with your own tools.
          </p>
          <div className="mt-6 inline-flex items-center gap-2 px-4 py-2 bg-slate-800 rounded-lg border border-slate-700">
            <Code className="w-4 h-4 text-orange-500" />
            <span className="text-slate-300 text-sm font-mono">POST /api/firewall</span>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderHow = () => (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="bg-green-500/20 p-3 rounded-lg">
            <ArrowRight className="w-8 h-8 text-green-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-2">How an API Works</h2>
            <p className="text-slate-300 text-lg">
              Understanding the request-response cycle step by step.
            </p>
          </div>
        </div>
      </Card>

      {/* Flow Steps */}
      <div className="grid grid-cols-1 gap-4">
        {/* Step 1 */}
        <Card className="border-blue-500/30">
          <div className="flex items-start gap-4">
            <div className="bg-blue-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-blue-400 font-bold text-xl">1</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">Client Sends a Request</h3>
              <p className="text-slate-300 mb-3">
                You (the client) initiate communication by sending a request to the API.
              </p>
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-slate-400 text-sm mb-2">Examples of clients:</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                  <div className="bg-slate-800 rounded px-3 py-2 text-cyan-400 font-mono">Browser</div>
                  <div className="bg-slate-800 rounded px-3 py-2 text-cyan-400 font-mono">Postman</div>
                  <div className="bg-slate-800 rounded px-3 py-2 text-cyan-400 font-mono">CLI Command</div>
                  <div className="bg-slate-800 rounded px-3 py-2 text-cyan-400 font-mono">Python/JS</div>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Step 2 */}
        <Card className="border-purple-500/30">
          <div className="flex items-start gap-4">
            <div className="bg-purple-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-purple-400 font-bold text-xl">2</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">API Receives & Validates Request</h3>
              <p className="text-slate-300 mb-3">
                The API checks if your request is valid before processing it.
              </p>
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-slate-400 text-sm mb-2">Validation checks:</p>
                <ul className="space-y-1 text-sm text-slate-300">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Is the endpoint valid?
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Is the HTTP method correct?
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    Is the authentication token valid?
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </Card>

        {/* Step 3 */}
        <Card className="border-orange-500/30">
          <div className="flex items-start gap-4">
            <div className="bg-orange-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-orange-400 font-bold text-xl">3</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">Backend Performs the Action</h3>
              <p className="text-slate-300 mb-3">
                The server processes your request and executes the necessary operations.
              </p>
              <div className="bg-slate-700/30 rounded-lg p-3">
                <p className="text-slate-400 text-sm mb-2">Common actions:</p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
                  <div className="flex items-center gap-2 text-slate-300">
                    <Database className="w-4 h-4 text-blue-400" />
                    Query database
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <ShieldCheck className="w-4 h-4 text-green-400" />
                    Apply firewall rule
                  </div>
                  <div className="flex items-center gap-2 text-slate-300">
                    <Code className="w-4 h-4 text-purple-400" />
                    Process data
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Card>

        {/* Step 4 */}
        <Card className="border-green-500/30">
          <div className="flex items-start gap-4">
            <div className="bg-green-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-green-400 font-bold text-xl">4</span>
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">API Returns a Response</h3>
              <p className="text-slate-300 mb-3">
                The API sends back the result in a structured format (usually JSON).
              </p>
              <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
                <p className="text-slate-400 text-xs mb-2">Example JSON Response:</p>
                <pre className="text-green-400 text-sm font-mono overflow-x-auto">
{`{
  "success": true,
  "message": "Rule - deny out to port 103/tcp with (IPv4:True IPv6:True) is added successfully"
}`}
                </pre>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Visual Flow */}
      <Card className="bg-gradient-to-r from-slate-800 to-slate-900 border-slate-700">
        <h3 className="text-xl font-bold text-white mb-4 text-center">Complete Flow</h3>
        <div className="flex items-center justify-center gap-3 flex-wrap">
          <div className="bg-blue-500/20 px-4 py-2 rounded-lg text-blue-400 font-semibold">Client</div>
          <ArrowRight className="w-5 h-5 text-slate-500" />
          <div className="bg-purple-500/20 px-4 py-2 rounded-lg text-purple-400 font-semibold">Request</div>
          <ArrowRight className="w-5 h-5 text-slate-500" />
          <div className="bg-orange-500/20 px-4 py-2 rounded-lg text-orange-400 font-semibold">API</div>
          <ArrowRight className="w-5 h-5 text-slate-500" />
          <div className="bg-red-500/20 px-4 py-2 rounded-lg text-red-400 font-semibold">Server</div>
          <ArrowRight className="w-5 h-5 text-slate-500" />
          <div className="bg-green-500/20 px-4 py-2 rounded-lg text-green-400 font-semibold">Response</div>
        </div>
      </Card>
    </div>
  );

  const renderConcepts = () => (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="flex items-start gap-4">
          <div className="bg-purple-500/20 p-3 rounded-lg">
            <Code className="w-8 h-8 text-purple-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-2">Important API Concepts</h2>
            <p className="text-slate-300 text-lg">
              Master these fundamental concepts to work effectively with APIs.
            </p>
          </div>
        </div>
      </Card>

      {/* Endpoints */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
            <span className="text-blue-400 font-bold">1</span>
          </div>
          Endpoints
        </h3>
        <p className="text-slate-300 mb-4">
          An <span className="text-blue-400 font-semibold">endpoint</span> is the specific URL "address" where you 
          call a particular function or resource.
        </p>
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <p className="text-slate-400 text-xs mb-2">Example endpoint:</p>
          <code className="text-green-400 text-sm font-mono">GET /api/firewall/status</code>
        </div>
      </Card>

      {/* HTTP Methods */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center">
            <span className="text-purple-400 font-bold">2</span>
          </div>
          HTTP Methods
        </h3>
        <p className="text-slate-300 mb-4">
          APIs use HTTP methods (also called "verbs") to indicate what action you want to perform.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-1 bg-green-500/20 text-green-400 font-mono text-sm rounded">GET</span>
              <span className="text-white font-semibold">Retrieve Data</span>
            </div>
            <p className="text-slate-400 text-sm">Fetch existing information without changing anything.</p>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 font-mono text-sm rounded">POST</span>
              <span className="text-white font-semibold">Create New Data</span>
            </div>
            <p className="text-slate-400 text-sm">Add new records or trigger actions.</p>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-1 bg-orange-500/20 text-orange-400 font-mono text-sm rounded">PUT</span>
              <span className="text-white font-semibold">Update Existing</span>
            </div>
            <p className="text-slate-400 text-sm">Modify or replace existing data.</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-1 bg-red-500/20 text-red-400 font-mono text-sm rounded">DELETE</span>
              <span className="text-white font-semibold">Remove Data</span>
            </div>
            <p className="text-slate-400 text-sm">Delete existing records or rules.</p>
          </div>
        </div>
      </Card>

      {/* Parameters */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-orange-500/20 rounded-lg flex items-center justify-center">
            <span className="text-orange-400 font-bold">3</span>
          </div>
          Parameters
        </h3>
        <p className="text-slate-300 mb-4">
          Extra information you send with your request. Can be in the URL (query), request body, or path.
        </p>
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <p className="text-slate-400 text-xs mb-2">Example with body parameters:</p>
          <pre className="text-sm font-mono mb-3">
            <span className="text-blue-400">POST</span> <span className="text-green-400">/api/firewall</span>
          </pre>
          <pre className="text-green-400 text-sm font-mono">
{`{
  "port": 22,
  "action": "deny",
  "protocol": "tcp"
}`}
          </pre>
        </div>
      </Card>

      {/* Status Codes */}
      <Card>
        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <div className="w-8 h-8 bg-green-500/20 rounded-lg flex items-center justify-center">
            <span className="text-green-400 font-bold">4</span>
          </div>
          HTTP Status Codes
        </h3>
        <p className="text-slate-300 mb-4">
          Every API response includes a status code that tells you if the request was successful or what went wrong.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-green-500/20 text-green-400 font-mono text-sm rounded font-bold">200</span>
              <span className="text-white font-semibold">OK</span>
            </div>
            <p className="text-slate-400 text-sm">Request succeeded.</p>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 font-mono text-sm rounded font-bold">201</span>
              <span className="text-white font-semibold">Created</span>
            </div>
            <p className="text-slate-400 text-sm">New resource created successfully.</p>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 font-mono text-sm rounded font-bold">400</span>
              <span className="text-white font-semibold">Bad Request</span>
            </div>
            <p className="text-slate-400 text-sm">Invalid input or parameters.</p>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 font-mono text-sm rounded font-bold">401</span>
              <span className="text-white font-semibold">Unauthorized</span>
            </div>
            <p className="text-slate-400 text-sm">Missing or invalid authentication token.</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-red-500/20 text-red-400 font-mono text-sm rounded font-bold">403</span>
              <span className="text-white font-semibold">Forbidden</span>
            </div>
            <p className="text-slate-400 text-sm">No permission to access this resource.</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-1 bg-red-500/20 text-red-400 font-mono text-sm rounded font-bold">500</span>
              <span className="text-white font-semibold">Server Error</span>
            </div>
            <p className="text-slate-400 text-sm">Something went wrong on the server.</p>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderSecurity = () => (
    <div className="space-y-6">
      {/* Header */}
      <Card className="bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-500/30">
        <div className="flex items-start gap-4">
          <div className="bg-red-500/20 p-3 rounded-lg">
            <Lock className="w-8 h-8 text-red-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-2">API Security & Authentication</h2>
            <p className="text-slate-300 text-lg">
              APIs often handle sensitive data and critical functions. Strong security is essential.
            </p>
          </div>
        </div>
      </Card>

      {/* Why Security Matters */}
      <Card className="border-orange-500/30">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-orange-500 flex-shrink-0 mt-1" />
          <div>
            <h3 className="text-xl font-bold text-white mb-2">Why API Security Matters</h3>
            <p className="text-slate-300 mb-3">
              Without proper security controls, APIs can become entry points for attackers. They can be:
            </p>
            <ul className="space-y-2 text-slate-300">
              <li className="flex items-start gap-2">
                <span className="text-red-400 mt-1">•</span>
                <span>Exploited to access sensitive data or resources</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-red-400 mt-1">•</span>
                <span>Abused through brute-force or automated attacks</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-red-400 mt-1">•</span>
                <span>Used to inject malicious code or commands</span>
              </li>
            </ul>
          </div>
        </div>
      </Card>

      {/* Security Concepts */}
      <div className="space-y-4">
        {/* API Keys */}
        <Card>
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-blue-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <Key className="w-6 h-6 text-blue-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">1. API Keys</h3>
              <p className="text-slate-300 mb-3">
                Unique strings that identify who is making the request. Often used for simple authentication.
              </p>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-4">
            <p className="text-slate-300 font-semibold mb-2 text-sm">Best Practices:</p>
            <ul className="space-y-2 text-sm text-slate-300">
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Keep API keys private — never expose them in client-side code
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Regenerate keys regularly
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Limit permissions (e.g., read-only keys)
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Combine with IP restrictions when possible
              </li>
            </ul>
          </div>
        </Card>

        {/* Access Tokens */}
        <Card>
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-purple-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <ShieldCheck className="w-6 h-6 text-purple-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">2. Access Tokens (Bearer Tokens)</h3>
              <p className="text-slate-300 mb-3">
                Short-lived tokens issued after successful login. More secure than API keys because they expire.
              </p>
            </div>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 border border-slate-700 mb-3">
            <p className="text-slate-400 text-xs mb-2">Used in headers like:</p>
            <code className="text-green-400 text-sm font-mono">Authorization: Bearer &lt;token&gt;</code>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-4">
            <p className="text-slate-300 font-semibold mb-2 text-sm">Security Tips:</p>
            <ul className="space-y-2 text-sm text-slate-300">
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Always use HTTPS to protect tokens in transit
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Store tokens securely (never in localStorage for sensitive apps)
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Validate token signatures if using JWT
              </li>
            </ul>
          </div>
        </Card>

        {/* Roles & Scopes */}
        <Card>
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-green-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <UserCheck className="w-6 h-6 text-green-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">3. Roles & Scopes</h3>
              <p className="text-slate-300 mb-3">
                Control what actions different users can perform using role-based access control (RBAC).
              </p>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-700/30 rounded-lg p-4">
              <p className="text-orange-400 font-semibold mb-2 text-sm">Roles (Broad Groups)</p>
              <div className="space-y-1 text-sm">
                <div className="bg-red-500/20 text-red-400 px-2 py-1 rounded inline-block mr-2">Admin</div>
                <div className="bg-blue-500/20 text-blue-400 px-2 py-1 rounded inline-block mr-2">Developer</div>
                <div className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded inline-block mr-2">CyberSec</div>
                <div className="bg-green-500/20 text-green-400 px-2 py-1 rounded inline-block">User</div>
              </div>
            </div>
            <div className="bg-slate-700/30 rounded-lg p-4">
              <p className="text-orange-400 font-semibold mb-2 text-sm">Scopes (Specific Permissions)</p>
              <ul className="space-y-1 text-sm text-slate-300">
                <li><code className="text-cyan-400">firewall.read</code></li>
                <li><code className="text-cyan-400">firewall.write</code></li>
                <li><code className="text-cyan-400">logs.read</code></li>
                <li><code className="text-cyan-400">admin.full</code></li>
              </ul>
            </div>
          </div>
          <div className="mt-3 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <p className="text-sm text-slate-300">
              <Info className="w-4 h-4 text-blue-400 inline mr-2" />
              <strong>Least Privilege Principle:</strong> Only grant the minimum permissions needed. 
              For example, a "read rules" scope should not allow modifying firewall rules.
            </p>
          </div>
        </Card>

        {/* Rate Limiting */}
        <Card>
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-orange-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <Clock className="w-6 h-6 text-orange-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">4. Rate Limiting</h3>
              <p className="text-slate-300 mb-3">
                Protects APIs from abuse and brute-force attacks by limiting how many requests can be made.
              </p>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-4">
            <p className="text-slate-300 text-sm mb-2">Example limits:</p>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-slate-800 rounded p-2 text-center">
                <p className="text-orange-400 font-bold">100 requests</p>
                <p className="text-slate-400">per minute</p>
              </div>
              <div className="bg-slate-800 rounded p-2 text-center">
                <p className="text-orange-400 font-bold">1000 requests</p>
                <p className="text-slate-400">per hour</p>
              </div>
            </div>
          </div>
        </Card>

        {/* Input Validation */}
        <Card>
          <div className="flex items-start gap-4 mb-4">
            <div className="bg-red-500/20 w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold text-white mb-2">5. Input Validation</h3>
              <p className="text-slate-300 mb-3">
                Prevents attacks like SQL injection or command injection by validating all incoming data.
              </p>
            </div>
          </div>
          <div className="bg-slate-700/30 rounded-lg p-4">
            <p className="text-slate-300 font-semibold mb-2 text-sm">APIs should:</p>
            <ul className="space-y-2 text-sm text-slate-300">
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Validate all JSON data and parameters
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Reject unexpected fields or invalid formats
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Sanitize inputs to prevent injection attacks
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                Use allowlists instead of blocklists when possible
              </li>
            </ul>
          </div>
        </Card>
      </div>

      {/* Summary */}
      <Card className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-green-500/30">
        <div className="text-center py-6">
          <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
          <h3 className="text-xl font-bold text-white mb-3">Remember: Security is Not Optional</h3>
          <p className="text-slate-300 max-w-2xl mx-auto">
            Every API endpoint is a potential attack surface. Always authenticate requests, validate inputs, 
            enforce least-privilege access and monitor for suspicious activity. Security should be built 
            in from the start, not added as an afterthought.
          </p>
        </div>
      </Card>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-3 rounded-lg">
            <Code className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">API Learning</h1>
            <p className="text-slate-400 mt-1">
              Master the fundamentals of APIs and how they power modern firewall automation
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <div className="flex gap-2 flex-wrap">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-all ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-blue-500 to-cyan-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {activeTab === 'intro' && renderIntro()}
      {activeTab === 'why' && renderWhy()}
      {activeTab === 'how' && renderHow()}
      {activeTab === 'concepts' && renderConcepts()}
      {activeTab === 'security' && renderSecurity()}
    </div>
  );
};

export default APILearning;